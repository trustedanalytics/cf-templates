# Trusted Analytics Platform AWS CloudFormation Templates

## Prerequisites

1. [Install virtualenv](https://virtualenv.readthedocs.org/en/latest/installation.html).
2. [Allocate an Elastic IP address](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/elastic-ip-addresses-eip.html#using-instance-addressing-eips-allocating).
3. [Create a key pair](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-key-pairs.html#having-ec2-create-your-key-pair).

## Parameters

| Name                         | Description | Default value |
| ---------------------------- | ----------- | ------------- |
| **`cfPassword`**             |             |               |
| **`cfSystemDomain`**         |             |               |
| **`cfElasticIP`**            |             |               |
| **`KeyName`**                |             |               |
| `ClouderaMasterInstanceType` |             | `m3.xlarge`   |
| `ClouderaWorkerCount`        |             | 3             |
| `ClouderaWorkerInstanceType` |             | `m3.xlarge`   |
| `NATInstanceType`            |             | `t2.micro`    |
| `cfRunnerZ1InstanceType`     |             | `c3.large`    |
| `cfRunnerZ1Instances`        |             | 1             |

You can use [xip.io](http://xip.io/) as a domain. For example for Elastic IP 75.101.155.119, domain 75.101.155.119.xip.io can be used.

## Creating an AWS CloudFormation template

[Create and activate](http://docs.python-guide.org/en/latest/dev/virtualenvs/#basic-usage) virtualenv:

```
$ virtualenv venv
$ source venv/bin/activate
```

Install requirements:

```
$ pip install -r requirements.txt
```

Configure `ansible-pull`:

```
$ export ANSIBLE_PULL_URL=https://<username>:<token>@github.com/<repository>/ansible-playbooks.git
$ export ANSIBLE_PULL_CHECKOUT=master
```

Create AWS CloudFormation descriptions:

```
$ ./TAP.py >TAP.template
```

## Creating an AWS CloudFormation stack using `cfn` script

Configure the [AWS CLI using environment variables](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-environment):

```
$ export AWS_ACCESS_KEY_ID=<access_key>
$ export AWS_SECRET_ACCESS_KEY=<secret_key>
```

```
$ cfn -c TAP.template -b <bucket> -p cfPassword=<password> -p cfSystemDomain=<domain> -p cfElasticIP=<elastic_ip> -p KeyName=<key_name> -r <region> -t -C CAPABILITY_IAM <stack>
```
