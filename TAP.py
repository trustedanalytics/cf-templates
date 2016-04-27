#!/usr/bin/env python
# pylint: disable=missing-docstring
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

import os

# pylint: disable=wildcard-import, unused-wildcard-import
from troposphere.constants import *
# pylint: enable=wildcard-import, unused-wildcard-import

from troposphere import (AWS_REGION, AWS_STACK_NAME, cloudformation, ec2, iam, Base64, FindInMap,
                         GetAtt, GetAZs, Join, Output, Parameter, Ref, Select, Tags, Template,
                         autoscaling)

import awacs.aws
import awacs.ec2
import awacs.iam
import awacs.sts

ANSIBLE_PULL_URL = os.getenv('ANSIBLE_PULL_URL',
                             'https://github.com/trustedanalytics/ansible-playbooks.git')

ANSIBLE_PULL_CHECKOUT = os.getenv('ANSIBLE_PULL_CHECKOUT', 'master')

ANSIBLE_GROUP_VARS = [
    'ntp_server=[\'0.amazon.pool.ntp.org\', \'1.amazon.pool.ntp.org\']\n',
    ]

TEMPLATE = Template()

TEMPLATE.add_version('2010-09-09')

TEMPLATE.add_mapping('Region2AMI', {
    EU_WEST_1:      {'Ubuntu': 'ami-cd0fd6be', 'RHEL': 'ami-78d29c0f'},
    AP_SOUTHEAST_1: {'Ubuntu': 'ami-9e7dbafd', 'RHEL': 'ami-faedeea8'},
    AP_SOUTHEAST_2: {'Ubuntu': 'ami-187a247b', 'RHEL': 'ami-7f0d4b45'},
    EU_CENTRAL_1:   {'Ubuntu': 'ami-bdc9dad1', 'RHEL': 'ami-8e96ac93'},
    AP_NORTHEAST_1: {'Ubuntu': 'ami-7386a11d', 'RHEL': 'ami-78379d78'},
    US_EAST_1:      {'Ubuntu': 'ami-bb156ad1', 'RHEL': 'ami-0d28fe66'},
    SA_EAST_1:      {'Ubuntu': 'ami-5040fb3c', 'RHEL': 'ami-d1d35ccc'},
    US_WEST_1:      {'Ubuntu': 'ami-a88de2c8', 'RHEL': 'ami-5b8a781f'},
    US_WEST_2:      {'Ubuntu': 'ami-b4a2b5d5', 'RHEL': 'ami-75f3f145'},
    })

UBUNTU_AMI = FindInMap('Region2AMI', Ref(AWS_REGION), 'Ubuntu')
RHEL_AMI = FindInMap('Region2AMI', Ref(AWS_REGION), 'RHEL')

def metadata(resource, ansible_group_name, ansible_group_vars=None):
    ansible_hosts = [
        '[{0}]\n'.format(ansible_group_name),
        'localhost ansible_connection=local\n',
        '\n'
        '[{0}:vars]\n'.format(ansible_group_name),
        ]

    ansible_hosts.extend(ANSIBLE_GROUP_VARS)

    if ansible_group_vars is not None:
        ansible_hosts.extend(ansible_group_vars)

    resource.Metadata = cloudformation.Metadata(
        # pylint: disable=line-too-long
        cloudformation.Init({
            'config': cloudformation.InitConfig(
                packages={
                    'apt': {
                        'git': []
                        }
                    },
                files=cloudformation.InitFiles({
                    '/etc/init/cfn-hup.conf': cloudformation.InitFile(
                        content=Join('', [
                            'start on runlevel [2345]\n',
                            'stop on runlevel [!2345]\n',
                            '\n',
                            'respawn\n',
                            '\n',
                            'exec cfn-hup\n'
                            ]),
                        ),
                    '/etc/cfn/cfn-hup.conf': cloudformation.InitFile(
                        content=Join('', [
                            '[main]\n',
                            'stack=', Ref(AWS_STACK_NAME), '\n',
                            'region=', Ref(AWS_REGION), '\n'
                            'interval=1\n'
                            ]),
                        ),
                    '/etc/ansible/ansible.cfg': cloudformation.InitFile(
                        content=Join('', [
                            '[defaults]\n',
                            'log_path=/var/log/ansible.log\n',
                            ]),
                        ),
                    '/etc/ansible/hosts': cloudformation.InitFile(
                        content=Join('', ansible_hosts),
                        ),
                    '/etc/cfn/hooks.conf': cloudformation.InitFile(
                        content=Join('', [
                            '[cfn-init]\n',
                            'triggers=post.update\n',
                            'path=Resources.{0}.Metadata\n'.format(resource.title),
                            'action=cfn-init -s ', Ref(AWS_STACK_NAME),
                            ' -r {0} --region '.format(resource.title), Ref(AWS_REGION), '\n',
                            'runas=root\n',
                            '\n',
                            '[ansible-pull]\n',
                            'triggers=post.add, post.update\n',
                            'path=Resources.{0}.Metadata\n'.format(resource.title),
                            'action=ansible-pull -U {0} -C {1} -f\n'.format(ANSIBLE_PULL_URL,
                                                                            ANSIBLE_PULL_CHECKOUT),
                            'runas=root\n'
                            ]),
                        ),
                    }),
                services={
                    'sysvinit': cloudformation.InitServices({
                        'cfn-hup': cloudformation.InitService(
                            files=['/etc/init/cfn-hup.conf', '/etc/cfn/cfn-hup.conf',
                                   '/etc/cfn/hooks.conf']
                            ),
                        }),
                    }
                ),
            }),
        )

def user_data(resource):
    resource.UserData = Base64(Join('', [
        '#!/bin/bash\n',
        '\n',
        'set -e\n',
        '\n',
        'curl -OsS https://bootstrap.pypa.io/get-pip.py\n',
        'python get-pip.py -q\n',
        '\n',
        # SEE: https://urllib3.readthedocs.org/en/latest/security.html#pyopenssl
        'pip install -q pyopenssl ndg-httpsclient pyasn1\n',
        '\n',
        'DEBIAN_FRONTEND=noninteractive\n',
        '\n',
        'apt-get -q update\n',
        'apt-get -qy install autoconf build-essential python-dev\n',
        '\n',
        'pip install -q ',
        'http://releases.ansible.com/ansible/ansible-2.0.0-0.9.rc4.tar.gz\n',
        '\n',
        'pip install ',
        'https://s3.amazonaws.com/cloudformation-examples/aws-cfn-bootstrap-latest.tar.gz\n',
        '\n',
        'cfn-init -s ', Ref(AWS_STACK_NAME), ' -r {} --region '.format(resource.title),
        Ref(AWS_REGION), '\n'
        ]))

# {{{vpc-with-single-public-subnet

VPC = TEMPLATE.add_resource(ec2.VPC(
    'VPC',
    EnableDnsHostnames=True,
    CidrBlock='10.0.0.0/16',
    Tags=Tags(Name=Join('-', [Ref(AWS_STACK_NAME), 'vpc'])),
    ))

INTERNET_GATEWAY = TEMPLATE.add_resource(ec2.InternetGateway(
    'InternetGateway',
    ))

ATTACH_GATEWAY = TEMPLATE.add_resource(ec2.VPCGatewayAttachment(
    'AttachGateway',
    InternetGatewayId=Ref(INTERNET_GATEWAY),
    VpcId=Ref(VPC),
    ))

PUBLIC_SUBNET = TEMPLATE.add_resource(ec2.Subnet(
    'PublicSubnet',
    VpcId=Ref(VPC),
    CidrBlock='10.0.0.0/24',
    AvailabilityZone=Select(0, GetAZs()),
    Tags=Tags(Name='public subnet'),
    ))

PUBLIC_ROUTE_TABLE = TEMPLATE.add_resource(ec2.RouteTable(
    'PublicRouteTable',
    VpcId=Ref(VPC),
    ))

TEMPLATE.add_resource(ec2.Route(
    'PublicRoute',
    DependsOn=ATTACH_GATEWAY.title,
    RouteTableId=Ref(PUBLIC_ROUTE_TABLE),
    DestinationCidrBlock='0.0.0.0/0',
    GatewayId=Ref(INTERNET_GATEWAY),
    ))

TEMPLATE.add_resource(ec2.SubnetRouteTableAssociation(
    'PublicSubnetRouteTableAssociation',
    SubnetId=Ref(PUBLIC_SUBNET),
    RouteTableId=Ref(PUBLIC_ROUTE_TABLE),
    ))

# }}}vpc-with-single-public-subnet

KEY_NAME = TEMPLATE.add_parameter(Parameter(
    'KeyName',
    Type=KEY_PAIR_NAME,
    ))

# {{{nat-gateway

NAT_EIP = TEMPLATE.add_resource(ec2.EIP(
    'NATEIP',
    DependsOn=ATTACH_GATEWAY.title,
    Domain='vpc',
    ))

NAT_GATEWAY = TEMPLATE.add_resource(ec2.NatGateway(
    'NATGateway',
    AllocationId=GetAtt(NAT_EIP, 'AllocationId'),
    SubnetId=Ref(PUBLIC_SUBNET),
    ))

# }}}nat-gateway

# {{{private-route-table

PRIVATE_ROUTE_TABLE = TEMPLATE.add_resource(ec2.RouteTable(
    'PrivateRouteTable',
    VpcId=Ref(VPC),
    ))

TEMPLATE.add_resource(ec2.Route(
    'PrivateRoute',
    RouteTableId=Ref(PRIVATE_ROUTE_TABLE),
    DestinationCidrBlock='0.0.0.0/0',
    NatGatewayId=Ref(NAT_GATEWAY),
    ))

# }}}private-route-table

# {{{key-name

KEY_NAME_WAIT_CONDITION_HANDLE = TEMPLATE.add_resource(cloudformation.WaitConditionHandle(
    'KeyNameWaitHandle',
    ))

KEY_NAME_WAIT_CONDITION = TEMPLATE.add_resource(cloudformation.WaitCondition(
    'KeyNameWaitCondition',
    Handle=Ref(KEY_NAME_WAIT_CONDITION_HANDLE),
    Timeout='900',
    ))

# }}}key-name

TERMINATION_PROTECTION_ENABLED = TEMPLATE.add_parameter(Parameter(
    'TerminationProtectionEnabled',
    Type=STRING,
    Default='true',
    AllowedValues=['true', 'false'],
    ))

# {{{jump-box

JUMP_BOX_ROLE = TEMPLATE.add_resource(iam.Role(
    'JumpBoxRole',
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

JUMP_BOX_POLICY = TEMPLATE.add_resource(iam.PolicyType(
    'JumpBoxPolicy',
    PolicyName='jump-box',
    PolicyDocument=awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.ec2.CreateKeyPair, awacs.ec2.DeleteKeyPair,
                        awacs.ec2.DescribeKeyPairs],
                Resource=['*'],
                ),
            ],
        ),
    Roles=[Ref(JUMP_BOX_ROLE)],
    ))

JUMP_BOX_INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'JumpBoxInstanceProfile',
    Roles=[Ref(JUMP_BOX_ROLE)],
    ))

JUMP_BOX_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'JumpBoxSecurityGroup',
    GroupDescription='jump box security group',
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

JUMP_BOX_INSTANCE = TEMPLATE.add_resource(ec2.Instance(
    'JumpBoxInstance',
    BlockDeviceMappings=[
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sda1',
            Ebs=ec2.EBSBlockDevice(
                VolumeSize='30',
                )
            ),
        ],
    DisableApiTermination=Ref(TERMINATION_PROTECTION_ENABLED),
    IamInstanceProfile=Ref(JUMP_BOX_INSTANCE_PROFILE),
    ImageId=UBUNTU_AMI,
    InstanceType=T2_SMALL,
    KeyName=Ref(KEY_NAME),
    SecurityGroupIds=[Ref(JUMP_BOX_SECURITY_GROUP)],
    SubnetId=Ref(PUBLIC_SUBNET),
    Tags=Tags(Name='Jump Box'),
    ))

JUMP_BOX_EIP = TEMPLATE.add_resource(ec2.EIP(
    'JumpBoxEIP',
    DependsOn=ATTACH_GATEWAY.title,
    Domain='vpc',
    InstanceId=Ref(JUMP_BOX_INSTANCE),
    ))

TEMPLATE.add_output(Output(
    'JumpBoxPublicDnsName',
    Value=GetAtt(JUMP_BOX_INSTANCE, 'PublicDnsName'),
    ))

# }}}jump-box

# {{{bosh

BOSH_SUBNET = TEMPLATE.add_resource(ec2.Subnet(
    'BOSHSubnet',
    VpcId=Ref(VPC),
    CidrBlock='10.0.1.0/24',
    AvailabilityZone=Select(0, GetAZs()),
    Tags=Tags(Name='BOSH subnet'),
    ))

TEMPLATE.add_resource(ec2.SubnetRouteTableAssociation(
    'BOSHSubnetRouteTableAssociation',
    SubnetId=Ref(BOSH_SUBNET),
    RouteTableId=Ref(PRIVATE_ROUTE_TABLE),
    ))

BOSH_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'BOSHSecurityGroup',
    GroupDescription='BOSH deployed VMs',
    SecurityGroupIngress=[
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
    'BOSHSecurityGroupIngress',
    IpProtocol='-1',
    FromPort='-1',
    ToPort='-1',
    SourceSecurityGroupId=Ref(BOSH_SECURITY_GROUP),
    GroupId=Ref(BOSH_SECURITY_GROUP),
    ))

# SEE: http://bosh.io/docs/aws-iam-instance-profiles.html#only-director

BOSH_DIRECTOR_ROLE = TEMPLATE.add_resource(iam.Role(
    'BOSHDirectorRole',
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

BOSH_DIRECTOR_POLICY = TEMPLATE.add_resource(iam.PolicyType(
    'BOSHDirectorPolicy',
    PolicyName='director',
    PolicyDocument=awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.aws.Action('ec2', '*')],
                Resource=['*'],
                ),
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.aws.Action('elasticloadbalancing', '*')],
                Resource=['*'],
                ),
            ],
        ),
    Roles=[Ref(BOSH_DIRECTOR_ROLE)],
    ))

BOSH_DIRECTOR_INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'BOSHDirectorInstanceProfile',
    Roles=[Ref(BOSH_DIRECTOR_ROLE)],
    ))

BOSH_SECURITY_GROUP.SecurityGroupIngress.extend([
    ec2.SecurityGroupRule(
        IpProtocol='tcp',
        FromPort='22',
        ToPort='22',
        SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
        ),
    ec2.SecurityGroupRule(
        IpProtocol='tcp',
        FromPort='6868',
        ToPort='6868',
        SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
        ),
    ec2.SecurityGroupRule(
        IpProtocol='tcp',
        FromPort='25555',
        ToPort='25555',
        SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
        ),
    ])

BOSH_DIRECTOR_POLICY.Roles.append(Ref(JUMP_BOX_ROLE))

# SEE: http://bosh.io/docs/aws-iam-instance-profiles.html#errors

JUMP_BOX_POLICY.PolicyDocument.Statement.append(awacs.aws.Statement(
    Effect=awacs.aws.Allow,
    Action=[awacs.iam.PassRole],
    Resource=[GetAtt(BOSH_DIRECTOR_ROLE, 'Arn')],
    ))

# }}}bosh

# {{{cf

CF_PRIVATE_SUBNET = TEMPLATE.add_resource(ec2.Subnet(
    'CFPrivateSubnet',
    VpcId=Ref(VPC),
    CidrBlock='10.0.2.0/24',
    AvailabilityZone=Select(0, GetAZs()),
    Tags=Tags(Name='Cloud Foundry subnet'),
    ))

TEMPLATE.add_resource(ec2.SubnetRouteTableAssociation(
    'CFPrivateSubnetRouteTableAssociation',
    SubnetId=Ref(CF_PRIVATE_SUBNET),
    RouteTableId=Ref(PRIVATE_ROUTE_TABLE),
    ))

CF_PUBLIC_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'CFPublicSecurityGroup',
    GroupDescription='cf-public',
    SecurityGroupIngress=[
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='80',
            ToPort='80',
            CidrIp='0.0.0.0/0',
            ),
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='443',
            ToPort='443',
            CidrIp='0.0.0.0/0',
            ),
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='4443',
            ToPort='4443',
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
    Tags=Tags(Name='cf-public'),
    VpcId=Ref(VPC),
    ))

CF_PASSWORD = TEMPLATE.add_parameter(Parameter(
    'CFPassword',
    NoEcho=True,
    Type=STRING,
    ))

CF_SYSTEM_DOMAIN = TEMPLATE.add_parameter(Parameter(
    'CFSystemDomain',
    Type=STRING,
    ))

CF_RUNNER_Z1_INSTANCES = TEMPLATE.add_parameter(Parameter(
    'CFRunnerZ1Instances',
    Type=NUMBER,
    Default='2',
    MinValue='1',
    ))

NGINX_EIP = TEMPLATE.add_parameter(Parameter(
    'NGINXEIP',
    Type=STRING,
    ))

CF_RUNNER_Z1_INSTANCE_TYPE = TEMPLATE.add_parameter(Parameter(
    'CFRunnerZ1InstanceType',
    Type=STRING,
    Default=R3_XLARGE,
    AllowedValues=[
        M4_LARGE, M4_XLARGE, M4_2XLARGE, M4_4XLARGE, M4_10XLARGE,
        M3_MEDIUM, M3_LARGE, M3_XLARGE, M3_2XLARGE,
        C4_LARGE, C4_XLARGE, C4_2XLARGE, C4_4XLARGE, C4_8XLARGE,
        C3_LARGE, C3_XLARGE, C3_2XLARGE, C3_4XLARGE, C3_8XLARGE,
        R3_LARGE, R3_XLARGE, R3_2XLARGE, R3_4XLARGE, R3_8XLARGE,
        ],
    ))

SMTP_HOST = TEMPLATE.add_parameter(Parameter(
    'SMTPHost',
    Type=STRING,
    ))

SMTP_SENDER_USER = TEMPLATE.add_parameter(Parameter(
    'SMTPSenderUser',
    Type=STRING,
    ))

SMTP_PASSWORD = TEMPLATE.add_parameter(Parameter(
    'SMTPPassword',
    Type=STRING,
    NoEcho=True,
    ))

SMTP_PORT = TEMPLATE.add_parameter(Parameter(
    'SMTPPort',
    Type=NUMBER,
    ))

SMTP_SENDER_EMAIL = TEMPLATE.add_parameter(Parameter(
    'SMTPSenderEmail',
    Type=STRING,
    ))

SMTP_SENDER_NAME = TEMPLATE.add_parameter(Parameter(
    'SMTPSenderName',
    Type=STRING,
    ))

QUAY_IO_USERNAME = TEMPLATE.add_parameter(Parameter(
    'QuayIoUsername',
    Type=STRING,
    ))

QUAY_IO_PASSWORD = TEMPLATE.add_parameter(Parameter(
    'QuayIoPassword',
    Type=STRING,
    NoEcho=True,
    ))

TEMPLATE.add_output(Output(
    'CFAPIURL',
    Value=Join('', ['https://api.', Ref(CF_SYSTEM_DOMAIN)]),
    ))

# }}}cf

# {{{kubernetes

KUBERNETES_SUBNET = TEMPLATE.add_resource(ec2.Subnet(
    'KubernetesSubnet',
    VpcId=Ref(VPC),
    CidrBlock='10.0.6.0/24',
    AvailabilityZone=Select(0, GetAZs()),
    Tags=Tags(Name='Kubernetes subnet'),
    ))

TEMPLATE.add_resource(ec2.SubnetRouteTableAssociation(
    'KubernetesSubnetRouteTableAssociation',
    SubnetId=Ref(KUBERNETES_SUBNET),
    RouteTableId=Ref(PRIVATE_ROUTE_TABLE),
    ))

# }}}kubernetes

# {{{consul

CONSUL_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'ConsulSecurityGroup',
    GroupDescription='Consul security group',
    SecurityGroupIngress=[
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

for proto in ('tcp', 'udp'):
    for interface, port in {'SerfLAN': 8301, 'SerfWAN': 8302, 'Server': 8300}.iteritems():
        TEMPLATE.add_resource(ec2.SecurityGroupIngress(
            'Consul{0}{1}SecurityGroupIngress'.format(interface, proto),
            IpProtocol=proto,
            FromPort=str(port),
            ToPort=str(port),
            SourceSecurityGroupId=Ref(CONSUL_SECURITY_GROUP),
            GroupId=Ref(CONSUL_SECURITY_GROUP),
            ))

# }}}consul

# {{{dns

DNS_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'DNSSecurityGroup',
    GroupDescription='DNS security group',
    SecurityGroupIngress=[
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

for proto in ('tcp', 'udp'):
    TEMPLATE.add_resource(ec2.SecurityGroupIngress(
        'DNS{0}SecurityGroupIngress'.format(proto),
        IpProtocol=proto,
        FromPort='53',
        ToPort='53',
        CidrIp=VPC.properties['CidrBlock'],
        GroupId=Ref(DNS_SECURITY_GROUP),
        ))

# }}}dns

# {{{cloudera

CLOUDERA_SUBNET = TEMPLATE.add_resource(ec2.Subnet(
    'ClouderaSubnet',
    VpcId=Ref(VPC),
    CidrBlock='10.0.5.0/24',
    AvailabilityZone=Select(0, GetAZs()),
    Tags=Tags(Name='Cloudera subnet'),
    ))

TEMPLATE.add_resource(ec2.SubnetRouteTableAssociation(
    'ClouderaSubnetRouteTableAssociation',
    SubnetId=Ref(CLOUDERA_SUBNET),
    RouteTableId=Ref(PRIVATE_ROUTE_TABLE),
    ))

CLOUDERA_ROLE = TEMPLATE.add_resource(iam.Role(
    'ClouderaRole',
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

CLOUDERA_POLICY = TEMPLATE.add_resource(iam.PolicyType(
    'ClouderaPolicy',
    PolicyName='cloudera',
    PolicyDocument=awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.ec2.DescribeInstances],
                Resource=['*'],
                ),
            ],
        ),
    Roles=[Ref(CLOUDERA_ROLE)],
    ))

CLOUDERA_MANAGER_INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'ClouderaManagerInstanceProfile',
    Roles=[Ref(CLOUDERA_ROLE)],
    ))

CLOUDERA_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'ClouderaSecurityGroup',
    GroupDescription='Cloudera security group',
    SecurityGroupIngress=[
        ec2.SecurityGroupRule(
            IpProtocol='-1',
            FromPort='-1',
            ToPort='-1',
            SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='-1',
            FromPort='-1',
            ToPort='-1',
            SourceSecurityGroupId=Ref(BOSH_SECURITY_GROUP),
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
    'ClouderaSecurityGroupIngress',
    IpProtocol='-1',
    FromPort='-1',
    ToPort='-1',
    SourceSecurityGroupId=Ref(CLOUDERA_SECURITY_GROUP),
    GroupId=Ref(CLOUDERA_SECURITY_GROUP),
    ))

CLOUDERA_MASTER_INSTANCE_TYPE = TEMPLATE.add_parameter(Parameter(
    'ClouderaMasterInstanceType',
    Type=STRING,
    Default=M3_XLARGE,
    AllowedValues=[
        M3_XLARGE, M3_2XLARGE,
        C3_XLARGE, C3_2XLARGE, C3_4XLARGE, C3_8XLARGE,
        R3_8XLARGE,
        ],
    ))

CLOUDERA_MANAGER_INSTANCE = TEMPLATE.add_resource(ec2.Instance(
    'ClouderaManagerInstance',
    BlockDeviceMappings=[
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sda1',
            Ebs=ec2.EBSBlockDevice(
                VolumeSize='30',
                )
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdb',
            VirtualName='ephemeral0'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdc',
            VirtualName='ephemeral1'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdd',
            VirtualName='ephemeral2'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sde',
            VirtualName='ephemeral3'
            ),
        ],
    DependsOn=KEY_NAME_WAIT_CONDITION.title,
    DisableApiTermination=Ref(TERMINATION_PROTECTION_ENABLED),
    IamInstanceProfile=Ref(CLOUDERA_MANAGER_INSTANCE_PROFILE),
    ImageId=RHEL_AMI,
    InstanceType=Ref(CLOUDERA_MASTER_INSTANCE_TYPE),
    KeyName=Join('-', [Ref(AWS_STACK_NAME), 'key']),
    SecurityGroupIds=[Ref(CLOUDERA_SECURITY_GROUP), Ref(DNS_SECURITY_GROUP), 
        Ref(CONSUL_SECURITY_GROUP)],
    SubnetId=Ref(CLOUDERA_SUBNET),
    Tags=Tags(Name='Cloudera Manager'),
    ))

CLOUDERA_MASTER_INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'ClouderaMasterInstanceProfile',
    Roles=[Ref(CLOUDERA_ROLE)],
    ))

CLOUDERA_MASTER_LAUNCH_CONFIGURATION = TEMPLATE.add_resource(autoscaling.LaunchConfiguration(
    'ClouderaMasterLaunchConfiguration',
    BlockDeviceMappings=[
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sda1',
            Ebs=ec2.EBSBlockDevice(
                VolumeSize='30',
                )
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdb',
            VirtualName='ephemeral0'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdc',
            VirtualName='ephemeral1'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdd',
            VirtualName='ephemeral2'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sde',
            VirtualName='ephemeral3'
            ),
        ],
    DependsOn=KEY_NAME_WAIT_CONDITION.title,
    IamInstanceProfile=Ref(CLOUDERA_MASTER_INSTANCE_PROFILE),
    ImageId=RHEL_AMI,
    InstanceType=Ref(CLOUDERA_MASTER_INSTANCE_TYPE),
    KeyName=Join('-', [Ref(AWS_STACK_NAME), 'key']),
    SecurityGroups=[Ref(CLOUDERA_SECURITY_GROUP), Ref(DNS_SECURITY_GROUP), 
        Ref(CONSUL_SECURITY_GROUP)],
    ))

CLOUDERA_MASTER_AUTO_SCALING_GROUP = TEMPLATE.add_resource(autoscaling.AutoScalingGroup(
    'ClouderaMasterAutoScalingGroup',
    DesiredCapacity='2',
    Tags=[autoscaling.Tag('Name', 'Cloudera Master', True)],
    LaunchConfigurationName=Ref(CLOUDERA_MASTER_LAUNCH_CONFIGURATION),
    MinSize='2',
    MaxSize='2',
    VPCZoneIdentifier=[Ref(CLOUDERA_SUBNET)],
    ))

CLOUDERA_WORKER_INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'ClouderaWorkerInstanceProfile',
    Roles=[Ref(CLOUDERA_ROLE)],
    ))

CLOUDERA_WORKER_INSTANCE_TYPE = TEMPLATE.add_parameter(Parameter(
    'ClouderaWorkerInstanceType',
    Type=STRING,
    Default=M3_XLARGE,
    AllowedValues=[
        M3_XLARGE, M3_2XLARGE,
        C3_XLARGE, C3_2XLARGE, C3_4XLARGE, C3_8XLARGE,
        R3_8XLARGE,
        ],
    ))

CLOUDERA_WORKER_LAUNCH_CONFIGURATION = TEMPLATE.add_resource(autoscaling.LaunchConfiguration(
    'ClouderaWorkerLaunchConfiguration',
    BlockDeviceMappings=[
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sda1',
            Ebs=ec2.EBSBlockDevice(
                VolumeSize='30',
                )
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdb',
            VirtualName='ephemeral0'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdc',
            VirtualName='ephemeral1'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sdd',
            VirtualName='ephemeral2'
            ),
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sde',
            VirtualName='ephemeral3'
            ),
        ],
    DependsOn=KEY_NAME_WAIT_CONDITION.title,
    IamInstanceProfile=Ref(CLOUDERA_WORKER_INSTANCE_PROFILE),
    ImageId=RHEL_AMI,
    InstanceType=Ref(CLOUDERA_WORKER_INSTANCE_TYPE),
    KeyName=Join('-', [Ref(AWS_STACK_NAME), 'key']),
    SecurityGroups=[Ref(CLOUDERA_SECURITY_GROUP)],
    ))

CLOUDERA_WORKER_COUNT = TEMPLATE.add_parameter(Parameter(
    'ClouderaWorkerCount',
    Type=NUMBER,
    Default='3',
    MinValue='1',
    ))

CLOUDERA_WORKER_AUTO_SCALING_GROUP = TEMPLATE.add_resource(autoscaling.AutoScalingGroup(
    'ClouderaWorkerAutoScalingGroup',
    DesiredCapacity=Ref(CLOUDERA_WORKER_COUNT),
    Tags=[autoscaling.Tag('Name', 'Cloudera Worker', True)],
    LaunchConfigurationName=Ref(CLOUDERA_WORKER_LAUNCH_CONFIGURATION),
    MinSize=Ref(CLOUDERA_WORKER_COUNT),
    MaxSize=Ref(CLOUDERA_WORKER_COUNT),
    VPCZoneIdentifier=[Ref(CLOUDERA_SUBNET)],
    ))

# }}}cloudera

# {{{docker

DOCKER_SUBNET = TEMPLATE.add_resource(ec2.Subnet(
    'DockerSubnet',
    VpcId=Ref(VPC),
    CidrBlock='10.0.4.0/24',
    AvailabilityZone=Select(0, GetAZs()),
    Tags=Tags(Name='Docker subnet'),
    ))

TEMPLATE.add_resource(ec2.SubnetRouteTableAssociation(
    'DockerSubnetRouteTableAssociation',
    SubnetId=Ref(DOCKER_SUBNET),
    RouteTableId=Ref(PRIVATE_ROUTE_TABLE),
    ))

DOCKER_BROKER_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'DockerBrokerPublicSecurityGroup',
    GroupDescription='docker-broker',
    SecurityGroupIngress=[
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='32768',
            ToPort='61000',
            SourceSecurityGroupId=Ref(CF_PUBLIC_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='udp',
            FromPort='32768',
            ToPort='61000',
            SourceSecurityGroupId=Ref(CF_PUBLIC_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='32768',
            ToPort='61000',
            SourceSecurityGroupId=Ref(CLOUDERA_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='udp',
            FromPort='32768',
            ToPort='61000',
            SourceSecurityGroupId=Ref(CLOUDERA_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='32768',
            ToPort='61000',
            SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='udp',
            FromPort='32768',
            ToPort='61000',
            SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
            ),
        ec2.SecurityGroupRule(
            IpProtocol='tcp',
            FromPort='4243',
            ToPort='4243',
            SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
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
    Tags=Tags(Name='docker-broker'),
    VpcId=Ref(VPC),
    ))

# }}}docker

# {{{nginx

NGINX_SECURITY_GROUP = TEMPLATE.add_resource(ec2.SecurityGroup(
    'NGINXSecurityGroup',
    GroupDescription='NGINX security group',
    SecurityGroupIngress=[],
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

NGINX_SECURITY_GROUP.SecurityGroupIngress.extend([
    ec2.SecurityGroupRule(
        IpProtocol='tcp',
        FromPort='22',
        ToPort='22',
        SourceSecurityGroupId=Ref(JUMP_BOX_SECURITY_GROUP),
        ),
    ])

BOSH_SECURITY_GROUP.SecurityGroupIngress.extend([
    ec2.SecurityGroupRule(
        IpProtocol='tcp',
        FromPort='80',
        ToPort='80',
        SourceSecurityGroupId=Ref(NGINX_SECURITY_GROUP),
        ),
    ])

NGINX_ROLE = TEMPLATE.add_resource(iam.Role(
    'NGINXRole',
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

NGINX_POLICY = TEMPLATE.add_resource(iam.PolicyType(
    'NGINXPolicy',
    PolicyName='nginx',
    PolicyDocument=awacs.aws.Policy(
        Statement=[
            awacs.aws.Statement(
                Effect=awacs.aws.Allow,
                Action=[awacs.ec2.DescribeInstances, awacs.ec2.DescribeSubnets],
                Resource=['*'],
                ),
            ],
        ),
    Roles=[Ref(NGINX_ROLE)],
    ))

NGINX_INSTANCE_PROFILE = TEMPLATE.add_resource(iam.InstanceProfile(
    'NGINXInstanceProfile',
    Roles=[Ref(NGINX_ROLE)],
    ))

NGINX_INSTANCE_TYPE = TEMPLATE.add_parameter(Parameter(
    'NGINXInstanceType',
    Type=STRING,
    Default=C4_LARGE,
    AllowedValues=[
        M4_LARGE, M4_XLARGE, M4_2XLARGE, M4_4XLARGE, M4_10XLARGE,
        M3_MEDIUM, M3_LARGE, M3_XLARGE, M3_2XLARGE,
        C4_LARGE, C4_XLARGE, C4_2XLARGE, C4_4XLARGE, C4_8XLARGE,
        C3_LARGE, C3_XLARGE, C3_2XLARGE, C3_4XLARGE, C3_8XLARGE,
        R3_LARGE, R3_XLARGE, R3_2XLARGE, R3_4XLARGE, R3_8XLARGE,
        ],
    ))

NGINX_INSTANCE = TEMPLATE.add_resource(ec2.Instance(
    'NGINXInstance',
    BlockDeviceMappings=[
        ec2.BlockDeviceMapping(
            DeviceName='/dev/sda1',
            Ebs=ec2.EBSBlockDevice(
                VolumeSize='30',
                )
            ),
        ],
    DependsOn=KEY_NAME_WAIT_CONDITION.title,
    DisableApiTermination=Ref(TERMINATION_PROTECTION_ENABLED),
    IamInstanceProfile=Ref(NGINX_INSTANCE_PROFILE),
    ImageId=UBUNTU_AMI,
    InstanceType=Ref(NGINX_INSTANCE_TYPE),
    KeyName=Join('-', [Ref(AWS_STACK_NAME), 'key']),
    SecurityGroupIds=[
        Ref(CF_PUBLIC_SECURITY_GROUP),
        Ref(NGINX_SECURITY_GROUP),
        Ref(CONSUL_SECURITY_GROUP),
        Ref(DOCKER_BROKER_SECURITY_GROUP)
        ],
    SubnetId=Ref(PUBLIC_SUBNET),
    Tags=Tags(Name='NGINX'),
    ))

NGINX_EIP_ASSOCIATION = TEMPLATE.add_resource(ec2.EIPAssociation(
    'NGINXEIPAssociation',
    EIP=Ref(NGINX_EIP),
    InstanceId=Ref(NGINX_INSTANCE),
    ))

NGINX_WAIT_CONDITION_HANDLE = TEMPLATE.add_resource(cloudformation.WaitConditionHandle(
    'NGINXWaitHandle',
    ))

NGINX_WAIT_CONDITION = TEMPLATE.add_resource(cloudformation.WaitCondition(
    'NGINXWaitCondition',
    Handle=Ref(NGINX_WAIT_CONDITION_HANDLE),
    Timeout='900',
    ))

user_data(NGINX_INSTANCE)
metadata(NGINX_INSTANCE, 'nginx', [
    'cf_system_domain=', Ref(CF_SYSTEM_DOMAIN), '\n'
    'docker_registry_password=', Ref(CF_PASSWORD), '\n',
    'cf_private_subnet_id=', Ref(CF_PRIVATE_SUBNET), '\n',
    'docker_subnet_id=', Ref(DOCKER_SUBNET), '\n',
    'nginx_wait_condition_handle=', Ref(NGINX_WAIT_CONDITION_HANDLE), '\n',
    ])

# }}}nginx

user_data(JUMP_BOX_INSTANCE)
metadata(JUMP_BOX_INSTANCE, 'jump-boxes', [
    'key_name=', Join('-', [Ref(AWS_STACK_NAME), 'key']), '\n',
    'key_name_wait_condition_handle=', Ref(KEY_NAME_WAIT_CONDITION_HANDLE), '\n',
    'bosh_subnet_id=', Ref(BOSH_SUBNET), '\n',
    'bosh_dns=[\'169.254.169.253\']\n',
    'bosh_default_security_groups=[\'', Ref(BOSH_SECURITY_GROUP), '\']\n',
    'bosh_iam_instance_profile=', Ref(BOSH_DIRECTOR_INSTANCE_PROFILE), '\n',
    'cf_private_subnet_id=', Ref(CF_PRIVATE_SUBNET), '\n',
    'cf_public_subnet_id=', Ref(PUBLIC_SUBNET), '\n',
    'cf_public_security_group=', Ref(CF_PUBLIC_SECURITY_GROUP), '\n',
    'cf_password=', Ref(CF_PASSWORD), '\n',
    'cf_system_domain=', Ref(CF_SYSTEM_DOMAIN), '\n',
    'cf_runner_z1_instances=', Ref(CF_RUNNER_Z1_INSTANCES), '\n',
    'cf_runner_z1_instance_type=', Ref(CF_RUNNER_Z1_INSTANCE_TYPE), '\n',
    'cf_smtp_host=', Ref(SMTP_HOST), '\n',
    'cf_smtp_sender_user=', Ref(SMTP_SENDER_USER), '\n',
    'cf_smtp_password=', Ref(SMTP_PASSWORD), '\n',
    'cf_smtp_port=', Ref(SMTP_PORT), '\n',
    'cf_smtp_sender_email=', Ref(SMTP_SENDER_EMAIL), '\n',
    'cf_smtp_sender_name=', Ref(SMTP_SENDER_NAME), '\n',
    'quay_io_username=', Ref(QUAY_IO_USERNAME), '\n',
    'quay_io_password=', Ref(QUAY_IO_PASSWORD), '\n',
    'docker_subnet_id=', Ref(DOCKER_SUBNET), '\n',
    'docker_broker_security_group=', Ref(DOCKER_BROKER_SECURITY_GROUP), '\n',
    ])

print TEMPLATE.to_json()

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4 colorcolumn=100
