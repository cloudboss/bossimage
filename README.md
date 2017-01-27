# bossimage

[![Build Status](https://travis-ci.org/cloudboss/bossimage.svg?branch=master)](https://travis-ci.org/cloudboss/bossimage)

Bossimage is a command line utility to convert an [Ansible role](http://docs.ansible.com/ansible/playbooks_roles.html) into an [Amazon EC2 AMI](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html).

Bossimage requires just one configuration file to be added to the base directory of an Ansible role. Once that is done, Bossimage may be used to build an EC2 instance, run the Ansible role on it, then "bake" it into an AMI. After the AMI is created, Bossimage can also build a test instance from it and run a test playbook on the instance.

Bossimage is inspired by both [Packer](https://www.packer.io/) and [Test Kitchen](http://kitchen.ci/), but much simpler than either. If you use both Ansible and AWS, you may find it useful.

Bossimage has been tested on both Linux and Windows targets in EC2.

# Installation
## Install from [PyPI](https://pypi.python.org/pypi)
```
pip install bossimage
```
## Install from source
```
git clone https://github.com/cloudboss/bossimage.git
cd bossimage
pip install -r requirements.txt
pip install .
```

# Quick Start

All interaction with Bossimage is done through an executable command called `bi`, which must always be run from the base directory of an Ansible role.

This introduction to Bossimage will explain how to do three things:

1. Make an EC2 instance and run Ansible on it (`bi make build`).
2. Make an AMI from the EC2 instance (`bi make image`).
3. Make a test instance from the AMI and run a test Ansible playbook on it (`bi make test`).

Later it will be explained how to do a few other things as well.

First, a small amount of configuration is necessary.

> Note: in this guide, all commands to be run from the shell are shown preceded by `> ` to indicate the shell prompt.

### Configuration
Bossimage requires a configuration file called `.boss.yml` to be placed in the root directory of the Ansible role. A minimal example of such a file is as follows:

```
platforms:
  - name: amz-2015092
    instance_type: t2.micro
    build:
      source_ami: amzn-ami-hvm-2015.09.2.x86_64-gp2
```

The example contains the most minimal configuration possible, using defaults for all settings except those which are required: the platform name, the [instance type](https://aws.amazon.com/ec2/instance-types/) and the source AMI used for the `build` phase.

Although Bossimage creates resources in AWS, it does not include any AWS authentication code, instead preferring to pass all authentication through to the underlying [SDK](http://boto3.readthedocs.io/en/latest/guide/configuration.html#guide-configuration) using [standard environment variables](https://blogs.aws.amazon.com/security/post/Tx3D6U6WSFGOK2H/A-New-and-Standardized-Way-to-Manage-Credentials-in-the-AWS-SDKs). Here is an example of gaining credentials by setting `AWS_PROFILE` and `AWS_DEFAULT_REGION` environment variables, assuming a credentials file has already been created.
```
> export AWS_PROFILE=uhuru
> export AWS_DEFAULT_REGION=us-west-1
```

If Bossimage is being run from an EC2 instance, an [IAM instance profile](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) may be used instead of environment variables, as described later.

### Running
Most `bi` subcommands require an _instance_ argument to be passed to them. The _instance_ is derived from a _platform_ together with a _profile_, i.e., `<platform>-<profile>`. In the `.boss.yml` configuration shown above, a single platform is defined with name `amz-2015092`. The profile is not explicitly defined, and is therefore `default`. So the instance is `amz-2015092-default`, and that will be the argument passed to the commands in this introduction.

Platforms and profiles will be described in more detail later.

#### bi make build
This builds an EC2 instance and runs the Ansible role on it. A unique ssh keypair is also created and assigned to the instance. This command, as with other `bi` commands, is idempotent and may be run multiple times without creating a new instance each time. Subsequent runs will simply run the Ansible role again on the existing instance.

Consider `bi make build` the entrypoint of Bossimage: it must be run before `bi make image` or `bi make test`.

```
> bi make build amz-2015092-default
Created keypair bossimage-oZL4NxUbAM
Created instance i-00000001
Waiting for instance to be running ... ok
Waiting for connection to 54.xxx.xxx.xxx:22 to be available ... ok

PLAY ***************************************************************************

TASK [setup] *******************************************************************
ok: [54.xxx.xxx.xxx]

TASK [test-role : add package httpd] *******************************************
changed: [54.xxx.xxx.xxx]

PLAY RECAP *********************************************************************
54.xxx.xxx.xxx             : ok=1    changed=1    unreachable=0    failed=0
```

#### bi make image
The primary goal of Bossimage is to create an AMI from an Ansible role, and that is what this command does. It may be run when `bi make build` has completed.

```
> bi make image amz-2015092-default
Created image ami-00000001 with name test-role.default.amz-2015092.hvm.x86_64.v2
Waiting for image to be available ... ok
Image is available
```

#### bi make test
It is useful to test that `bi make image` generated a correct AMI, and this is where `bi make test` comes into play.

This command is very similar to `bi make build`, in that it creates an EC2 instance and runs Ansible on it. However, it depends on a successful outcome of the `bi make image` command, as it uses the AMI created by that command as the source AMI of the EC2 test instance.

It also does not run the Ansible role on the instance, rather it runs a test playbook, which by default is `tests/test.yml`, relative to the root of the Ansible role directory. When creating an Ansible role with the `ansible-galaxy` command, this test playbook is added by default. For this default test playbook to work with Bossimage, only one small change is needed: to changed the `hosts` in the playbook from `localhost` to `test`.

```
> bi make test amz-2015092-default
Created instance i-00000002
Waiting for instance to be running ... ok
Waiting for connection to 52.xxx.xxx.xxx:22 to be available ... ok

PLAY [test] ********************************************************************

TASK [setup] *******************************************************************
ok: [52.xxx.xxx.xxx]

TASK [check that httpd is installed] *******************************************
ok: [52.xxx.xxx.xxx]

TASK [check that port 80 is listening] **********************************************
ok: [52.xxx.xxx.xxx]

PLAY RECAP *********************************************************************
52.xxx.xxx.xxx               : ok=2    changed=0    unreachable=0    failed=0
```

### Conclusion
Having run these three commands, you will have seen the major functionality of Bossimage. You will have created an AMI and then tested it.

Continue reading to learn:

* How to build multiple "flavors" of AMIs for a given platform
* A shortcut for logging into build and test instances
* Clean up instances and keypairs used during the build and test phases
* Clean up AMIs that did not pass tests

# Bossimage

### Instances, Platforms, and Profiles
Most of the `bi` subcommands, such as `make build` or `make test`, take an argument called the _instance_. An instance is defined by a _platform_ and a _profile_, such as `rhel6-default`, where `rhel6` is the platform and `default` is the profile.

#### Platform
The platform defines the source AMI and other settings related to creating an EC2 instance, such as security groups and block device mappings. It also defines connection settings for Ansible to reach the instance, such as ssh or winrm ports and default username.

#### Profile
The profile defines variables that will be passed to Ansible through its `--extra-vars` argument. By defining multiple profiles, you can build multiple flavors of AMIs for a given platform.

For example, here is a `.boss.yml` with one platform and two profiles.

```
platforms:
  - name: ubuntu-16.04
    build:
      source_ami: ami-301f6f50
    instance_type: t2.micro
    username: ubuntu
    security_groups: [bossimage]

profiles:
  - name: apache
    extra_vars:
      packages:
        - apache2
  - name: nginx
    extra_vars:
      packages:
        - nginx
```

Running `bi list` will produce the output:

```
ubuntu-16.04-apache     Not created
ubuntu-16.04-nginx      Not created
```

Each of these platform and profile combinations, or instances, can be made into its own AMI.

If `profiles` is not defined, every platform has an implicit profile, called `default`. The `default` profile does not define any variables. Note that if `profiles` is defined, there is no longer any implicit `default` profile. In such cases you can define one that has no `extra_vars` attribute, if desired.

## .boss.yml
The `.boss.yml` file is placed in the root directory of an Ansible role. It is the only configuration necessary for using Bossimage.

To start, here is a full example for reference.

```
defaults:
  instance_type: m3.large

platforms:
  - name: centos-6
    instance_type: t2.micro
    username: centos
    connection_timeout: 600
    build:
      source_ami: 'CentOS Linux 6 x86_64 HVM EBS 1602-74e73035-3435-48d6-88e0-89cc02ad83ee-ami-21e6d54b.3'
    test:
      instance_type: m3.medium
    tags:
      Billing: xyz
      Description: Centos 6 Build Instance

  - name: amz-2015092
    build:
      source_ami: amzn-ami-hvm-2015.09.2.x86_64-gp2
    image:
      ami_name: '%(role)s-%(profile)s-%(version)s-%(platform)s'
    block_device_mappings:
      - device_name: /dev/sdf
        ebs:
          volume_size: 100
          volume_type: gp2
          delete_on_termination: true
    tags:
      Billing: xyz
      Description: Amazon Linux 201509 Build Instance

profiles:
  - name: default
  - name: nginx
    extra_vars:
      packages:
        - nginx
        - tcpdump
```

A `.boss.yml` file has three possible sections:

* `defaults`: This section is optional, and contains default values to be used within `platforms` when not provided there.
* `platforms`: This section is required, and defines a list of platforms to build instances from. There must be at least one platform defined in a `.boss.yml` configuration. Each platform defined in the `platforms` section contains its own subsections for each of the three phases `build`, `image`, and `test`.
* `profiles`: This section is optional. In here, sets of variables may be defined to modify each platform defined in the `platforms` section. If this section is not given, each platform will have a profile called `default`, with no additional variables set.

### defaults
The `defaults` section may contain the following variables.

* `instance_type` - type: _string_, default: `t2.micro`

 The EC2 instance type.

* `username` - type: _string_, default: `ec2-user`

 The user that Ansible will use to connect to the instance.

* `connection` - type: _string_, default: `ssh`

 The type of connection that Ansible will use, may be either `ssh` or `winrm`.

* `connection_timeout` - type: _integer_, default: `300`

 The amount of time in seconds before Bossimage will give up trying to make an Ansible connection.

* `port` - type: _integer_, default: 22

 The port used to connect with Ansible.

* `associate_public_ip_address` - type: _bool_, default: `true`

 Whether or not to associate a public IP address to the instance.

* `subnet` - type _string_

 The subnet in which the instance will be located.

* `security_groups` - type _list_ of _string_, default `[]`

 The security groups that are associated with the instance.

* `tags` - type _map_ of _string_ to _string_, default `{}`

 A map of key/value pairs to be used for tagging the instance.


* `user_data` - type: _map_ or _string_, default: `''`

 This is the [user data](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html) that will be passed into the EC2 instance. If it is given as a map, then it must have the key `file`, which is the path to a file containing the user data.

 Example:

 ```
defaults:
  user_data:
    file: ./user-data.txt
 ```

 If the type is a string, then it is passed verbatim as the user data for the instance.

 Example:

 ```
 user_data: |
   #!/bin/sh
   yum update -y
 ```

* `block_device_mappings` - type: _list_ of _map_, default: `[]`

 Devices to be attached to the EC2 instance that will be part of a baked image.

 Each item in the list is a map as described in the [BlockDeviceMappings](http://boto3.readthedocs.io/en/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances) property passed to the boto3 create_instances operation. The only difference is that in. boss.yml, "CamelCase" properties should be converted to "snake_case".

### platforms
The `platforms` section contains a list of configurations, one for each defined platform. Each platform configuration must have the keys:

* `name` - type _string_, required

* `build` - type _map_, required

 See [build](#build) below.

* `image` - type _map_, optional

 See [image](#image) below.

* `test` - type _map_, optional

 See [test](#test) below.

The platform configuration may also contain any of the variables from `defaults`, and will override any of the definitions from there.

#### build
The `build` section of a platform is required and may include any of the variables from `defaults`. They will override any of the definitions given there or in the parent platform.

The `build` section also has the following keys:

* `source_ami` - type: _string_, required

 This is the source AMI to build the instance from. It may be given as an AMI ID or name, from which the ID will be found.

* `become` - type: _boolean_, default: `true`

 This tells Ansible whether or not to "become" the superuser.

#### image
The `image` section of a platform may have the following key:

* `ami_name` - type: _string_, default: `'%(role)s.%(profile)s.%(platform)s.%(vtype)s.%(arch)s.%(version)s'`

 This is a [Python formatting string](https://docs.python.org/2/library/stdtypes.html#string-formatting) to use for generating the AMI name. The string may contain any of the variables:

 * `role`: Name of Ansible role
 * `profile`: Name of profile used from `.boss.yml`
 * `platform`: Name of platform used from `.boss.yml`
 * `vtype`:  Virtualization type, e.g. `hvm`
 * `arch`:  Architecture, e.g. `x86_64`
 * `version`: Ansible role version, see [Role Versions](#role-versions).
 * `hv`:  Hypervisor, e.g. `xen`

Of course, `ami_name` may also be a string used verbatim without any interpolated variables in it.

#### test
The `test` section of a platform may include any of the variables from `defaults`. They will override any of the definitions given there or in the parent platforms.

In addition, the `test` section may have the following key:

* `playbook` - type: _string_, default: `tests/test.yml`

 This is the playbook to run during the test phase. The default value is the same as the test playbook that is created by running `ansible-galaxy init` to create a new Ansible role.

## Commands
The `bi` command must always be run from the root directory of an Ansible role, where the `.boss.yml` file is located.

#### bi list
List instances available to be built that are configured in .boss.yml. The status of the instance is shown, which may be either `Created` or `Not created`.

```
> bi list
amz-2015092-default     Created
ubuntu-16.10-default    Not created
```

#### bi make build

```
> bi make build <instance> [-v|--verbosity]
```

This builds an EC2 instance and runs the Ansible role on it. A unique ssh keypair is also created and assigned to the instance. This command is idempotent and may be run multiple times without creating a new instance each time. Subsequent runs will simply run the Ansible role again on the existing instance.

If your Ansible role has a `requirements.yml` file, then the `ansible-galaxy` command will be used to install the dependencies listed there.

The `-v`, or `--verbosity` option gets passed through to Ansible. It may be repeated up to four times to increase the Ansible's verbosity.

#### bi make image

```
> bi make image <instance> [--no-wait]
```

This builds an AMI from the instance created by running `bi make build`. This command will not run unless `bi make build` has run and written its state to `.boss/<instance>-state.yml`.

By default this command will complete when the image is available. You may pass the option `--no-wait` to this command so that it does not wait for the image to be available.

#### bi make test

```
> bi make test <instance> [-v|--verbosity]
```

This builds an EC2 instance from the AMI created by running `bi make image`, then runs the test playbook on it. This command will not run unless `bi make image` has run and written its state to `.boss/<instance>-state.yml`.

As with `bi make build`, `ansible-galaxy` will be used to install any role dependencies used by the test playbook, but `ansible-galaxy` will look for them in `tests/requirements.yml`.

The `-v`, or `--verbosity` option gets passed through to Ansible. It may be repeated up to four times to increase the Ansible's verbosity.

#### bi clean build

```
> bi clean build <instance>
```

This deletes the instance created by `bi make build`.

#### bi clean image

```
> bi clean image <instance>
```

This deletes the AMI created by `bi make image`.

#### bi clean test

```
> bi clean test <instance>
```

This deletes the instance created by `bi make build`.

#### bi login

```
> bi login <instance>
```

This command works only on instances where the platform is configured for ssh connections, which is the default. By default this command logs into the `build` phase instance, but this may be changed by passing the `-p|--phase` argument, which may be either `build` or `test`.

```
> bi login -p test <instance>
```

#### bi version
The command outputs the version of Bossimage.

## Role Versions
Ansible Galaxy does not provide a way to define a role's version in its metadata, it relies on git tags for versioning. So Bossimage does not have anything it can parse to discover the version of a role.

Instead, you can put a file in the root of the repository called `.role-version` which contains the version string. Bossimage also supports defining the version in the environment variable `BI_ROLE_VERSION`.

If neither the `.role-version` file or the `BI_ROLE_VERSION` environment variable are present, then a default version `unset` is used.

## Authenticating with AWS
`bossimage` uses standard AWS SDK environment variables for authentication, which are described in the [boto3 documentation](http://boto3.readthedocs.org/en/latest/guide/configuration.html#configuration).

The simplest way to authenticate if you are not running `bossimage` on an EC2 instance is to configure `~/.aws/credentials` with a [profile](http://docs.aws.amazon.com/cli/latest/userguide/cli-chap-getting-started.html#cli-multiple-profiles) and pass its name in the environment variable `AWS_PROFILE`.

If you are running `bossimage` on an EC2 instance, you may assign the instance an [IAM role](http://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_switch-role-ec2_instance-profiles.html) upon creation, and then you do not need to pass any credentials. The IAM role should have the policy shown below.

```
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ec2:CreateImage",
                "ec2:CreateKeyPair",
                "ec2:CreateTags",
                "ec2:DeleteKeyPair",
                "ec2:DeregisterImage",
                "ec2:DescribeImages",
                "ec2:DescribeInstances",
                "ec2:RunInstances",
                "ec2:TerminateInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

## Region
You must set the AWS region you are running in. To do this, set the `AWS_DEFAULT_REGION` environment variable.

# Rationale
All I want is to spin up an EC2 instance in AWS, run an [Ansible](http://docs.ansible.com/ansible/index.html) role on it, bake it into an image, and run some tests to verify the correctness of the image.

### Comparison with Packer
Packer is a tool for creating VM and Docker images for a multitude of cloud providers and for local use.

Packer does more than I need; I only need to create EC2 AMIs. But still it doesn't do quite enough: it doesn't provide a development phase for rapid iterative development of an Ansible role. You always have to start from the beginning with a new instance.

Bossimage creates EC2 images and provides a development phase before creating an image, and a testing phase for when the image has been created.

### Comparison with Test Kitchen
Test Kitchen is a tool for testing Chef cookbooks, but can be used to test Ansible and other configuration management tools using third party plugins. It can create VM instances with Vagrant and various cloud providers to use for developing.

Test Kitchen does more than I need; I only need to test Ansible in EC2. But still it doesn't do quite enough: it doesn't provide an AMI creation phase.

Bossimage creates EC2 instances and runs Ansible on them, and provides image creation and image testing phases.
