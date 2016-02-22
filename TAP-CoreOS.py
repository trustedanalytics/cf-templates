#!/usr/bin/env python
# pylint: disable=missing-docstring,invalid-name
# Copyright (c) 2015 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

# pylint: disable=wildcard-import, unused-wildcard-import
from troposphere.constants import *
# pylint: enable=wildcard-import, unused-wildcard-import

from troposphere import (AWS_REGION, ec2, iam, Base64, FindInMap, Join, Parameter, Ref, Template,
                         autoscaling, policies)

import awacs.ec2
import awacs.iam
import awacs.sts

TEMPLATE = Template()

TEMPLATE.add_version('2010-09-09')

TEMPLATE.add_mapping('RegionMap', {
    EU_CENTRAL_1:   {'AMI': 'ami-93f4ecff'},
    AP_NORTHEAST_1: {'AMI': 'ami-d56c56bb'},
    SA_EAST_1:      {'AMI': 'ami-fb129297'},
    AP_SOUTHEAST_2: {'AMI': 'ami-8bdffbe8'},
    AP_SOUTHEAST_1: {'AMI': 'ami-22529d41'},
    US_EAST_1:      {'AMI': 'ami-38c4eb52'},
    US_WEST_2:      {'AMI': 'ami-ddfc1abd'},
    US_WEST_1:      {'AMI': 'ami-cc2254ac'},
    EU_WEST_1:      {'AMI': 'ami-9f8f39ec'},
    })

VPC = TEMPLATE.add_parameter(Parameter(
    'VPC',
    Type=VPC_ID,
    ))

ROLE = TEMPLATE.add_resource(iam.Role(
    'Role',
    AssumeRolePolicyDocument=awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.sts.AssumeRole],
                Principal=awacs.aws.Principal('Service', ['ec2.amazonaws.com']),
                ),
            ],
        ),
    ))

POLICY = TEMPLATE.add_resource(iam.PolicyType(
    'Policy',
    PolicyName='coreos',
    PolicyDocument=awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.ec2.EC2Action('Describe*')],
                Resource=['*'],
                ),
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.aws.Action('autoscaling', 'Describe*')],
                Resource=['*'],
                ),
            ],
        ),
    Roles=[Ref(ROLE)],
    ))

INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'InstanceProfile',
    Roles=[Ref(ROLE)],
    ))

INSTANCE_TYPE = TEMPLATE.add_parameter(Parameter(
    'InstanceType',
    Type=STRING,
    Default=M4_LARGE,
    AllowedValues=[M4_LARGE, M4_XLARGE, M4_2XLARGE, M4_4XLARGE, M4_10XLARGE],
    ))

KEY_NAME = TEMPLATE.add_parameter(Parameter(
    'KeyName',
    Type=KEY_PAIR_NAME,
    ))

SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'SecurityGroup',
    GroupDescription='CoreOS instances',
    SecurityGroupIngress=[
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='22',
            ToPort='22',
            CidrIp='0.0.0.0/0',
            ),
        ],
    SecurityGroupEgress=[
        ec2.SecurityGroupRule(
            IpProtocol='-1',
            FromPort='-1',
            ToPort='-1',
            CidrIp='0.0.0.0/0',
            ),
        ],
    VpcId=Ref(VPC),
    ))

TEMPLATE.add_resource(ec2.SecurityGroupIngress(
    'etcdClientCommunicationSecurityGroupIngress',
    IpProtocol='tcp',
    FromPort='2379',
    ToPort='2379',
    SourceSecurityGroupId=Ref(SECURITY_GROUP),
    GroupId=Ref(SECURITY_GROUP),
    ))

TEMPLATE.add_resource(ec2.SecurityGroupIngress(
    'etcdServerToServerCommunicationSecurityGroupIngress',
    IpProtocol='tcp',
    FromPort='2380',
    ToPort='2380',
    SourceSecurityGroupId=Ref(SECURITY_GROUP),
    GroupId=Ref(SECURITY_GROUP),
    ))

LAUNCH_CONFIGURATION = TEMPLATE.add_resource(autoscaling.LaunchConfiguration(
    'LaunchConfiguration',
    IamInstanceProfile=Ref(INSTANCE_PROFILE),
    ImageId=FindInMap('RegionMap', Ref(AWS_REGION), 'AMI'),
    InstanceType=Ref(INSTANCE_TYPE),
    KeyName=Ref(KEY_NAME),
    SecurityGroups=[Ref(SECURITY_GROUP)],
    UserData=Base64(Join('', [
        '#cloud-config\n\n',
        'coreos:\n',
        '  etcd2:\n',
        '    advertise-client-urls: http://$private_ipv4:2379\n',
        '    initial-advertise-peer-urls: http://$private_ipv4:2380\n',
        '    listen-client-urls: http://0.0.0.0:2379\n',
        '    listen-peer-urls: http://$private_ipv4:2380\n',
        '  units:\n',
        '    - name: etcd-peers.service\n',
        '      command: start\n',
        '      content: |\n',
        '        [Unit]\n',
        '        Description=Write a file with the etcd peers that we should bootstrap to\n',
        '        After=docker.service\n'
        '        Requires=docker.service\n\n',
        '        [Service]\n',
        '        Type=oneshot\n',
        '        RemainAfterExit=yes\n',
        '        ExecStart=/usr/bin/docker pull monsantoco/etcd-aws-cluster:latest\n',
        '        ExecStart=/usr/bin/docker run --rm=true -v /etc/sysconfig/:/etc/sysconfig/ ',
        'monsantoco/etcd-aws-cluster:latest\n',
        '    - name: etcd2.service\n'
        '      command: start\n',
        '      drop-ins:\n'
        '        - name: 30-etcd_peers.conf\n',
        '          content: |\n',
        '            [Unit]\n',
        '            After=etcd-peers.service\n'
        '            Requires=etcd-peers.service\n\n',
        '            [Service]\n',
        '            # Load the other hosts in the etcd leader autoscaling group from file\n',
        '            EnvironmentFile=/etc/sysconfig/etcd-peers\n',
        '    - name: fleet.service\n',
        '      command: start\n',
        ])),
    ))

SUBNET = TEMPLATE.add_parameter(Parameter(
    'Subnet',
    Type=SUBNET_ID,
    ))

AUTO_SCALING_GROUP = TEMPLATE.add_resource(autoscaling.AutoScalingGroup(
    'AutoScalingGroup',
    DesiredCapacity='3',
    Tags=[autoscaling.Tag('Name', 'etcd', True)],
    LaunchConfigurationName=Ref(LAUNCH_CONFIGURATION),
    MinSize='3',
    MaxSize='12',
    VPCZoneIdentifier=[Ref(SUBNET)],
    UpdatePolicy=policies.UpdatePolicy(
        AutoScalingRollingUpdate=policies.AutoScalingRollingUpdate(
            MinInstancesInService='2',
            MaxBatchSize='1',
            ),
        ),
    ))

print TEMPLATE.to_json()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 colorcolumn=100
