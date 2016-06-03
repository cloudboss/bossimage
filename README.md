# bossimage

[![Build Status](https://travis-ci.org/cloudboss/bossimage.svg?branch=master)](https://travis-ci.org/cloudboss/bossimage)

Create a role with `ansible-galaxy` and drop a `.boss.yml` into the directory it created. Use `bi run` to create an EC2 instance and run the Ansible role on it. Modify the role and rerun as necessary until satisfied. Use `bi image` to bake it into an image. Clean up with `bi delete`.

`bossimage` is inspired by both [Packer](https://www.packer.io/) and [Test Kitchen](http://kitchen.ci/), but much simpler than either. If you use both Ansible and AWS, you may find it useful.

`bossimage` has been tested on both Linux and Windows targets in EC2.

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

# Usage
## Quick start
After installation, the `bi` command is provided, which has the subcommands `list`, `run`, `image`, `delete`, `login`, and `version`.

AWS region and credentials must be set.

```
export AWS_PROFILE=uhuru
export AWS_DEFAULT_REGION=us-west-1
```

#### ansible-galaxy
Create an Ansible role.

```
$ ansible-galaxy init test-role
$ cd test-role
$ cat > .boss.yml <<EOF
platforms:
  - name: amz-2015092
    instance_type: t2.micro
    source_ami: amzn-ami-hvm-2015.09.2.x86_64-gp2
EOF
```

Modify the role to add tasks, handlers, and vars as desired.

#### list
List instances available to be built that are configured in .boss.yml:
```
$ bi list
amz-2015092-default    Created
```

#### run
Build an EC2 instance and run the Ansible role on it:
```
$ bi run amz-2015092-default
Created instance i-00000000
Waiting for instance to be available ... ok
Waiting for connection to 54.xxx.xxx.xxx:22 to be available ... ok

PLAY ***************************************************************************

TASK [setup] *******************************************************************
ok: [54.xxx.xxx.xxx]

TASK [test-role : add package httpd] *******************************************
changed: [54.xxx.xxx.xxx]

PLAY RECAP *********************************************************************
54.xxx.xxx.xxx             : ok=1    changed=1    unreachable=0    failed=0
```

More verbose output may be provided with `-v`, up to four times. This is passed through to `ansible-playbook`.

```
$ bi run amz-2015092-default -vvvv
```

#### image
Bake an image.

```
$ bi image amz-2015092-default
Created image ami-00000000 with name test-role.default.amz-2015092.hvm.x86_64.v2
Waiting for image to be available ... ok
Image is available
```

#### delete
Clean up the EC2 instance and generated keypair.

```
$ bi delete amz-2015092-default
```

#### login
Log into an EC2 instance that has been created with `run`. This is only supported for `ssh` connections.

```
$ bi login amz-2015092-default
Last login: Tue Mar 29 15:18:01 2016 from kalawa.example.com
[ec2-user@ip-172-31-15-45 ~]$
```

#### version
Show version.

```
$ bi version
0.1.10
```

## More detail
### Authenticating with AWS
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
                "ec2:CreateKeyPair",
                "ec2:DeleteKeyPair",
                "ec2:DescribeImages",
                "ec2:CreateImage",
                "ec2:DescribeInstances",
                "ec2:RunInstances",
                "ec2:TerminateInstances"
            ],
            "Resource": "*"
        }
    ]
}
```

### Region
You must set the AWS region you are running in. To do this, set the `AWS_DEFAULT_REGION` environment variable.

### Configuring an Ansible role with a `.boss.yml`
`bossimage` must always be run from the root directory of an Ansible role, and is configured by a file called `.boss.yml` in that directory. The configuration is similar to the `.kitchen.yml` file used by Test Kitchen.

Example:

```
driver:
  instance_type: t2.micro

platforms:
  - name: ubuntu-16.04
    source_ami: ami-301f6f50
    username: ubuntu
    associate_public_ip_address: false
    subnet: professor
    security_groups: [mafikizolo]
    user_data:
      file: user_data.txt
    tags:
      Name: maphorisa

  - name: amz-2015092
    source_ami: amzn-ami-hvm-2015.09.2.x86_64-gp2
    connection_timeout: 333
    instance_type: m3.medium
    block_device_mappings:
      - device_name: /dev/sdf
        ebs:
          volume_size: 100
          volume_type: gp2
          delete_on_termination: true
    user_data: |
      #cloud-config
      system_info:
        default_user:
          name: oskido

profiles:
  - name: default
  - name: httpd
    extra_vars:
      packages:
        - httpd
```

There are three sections in the file: `driver`, `platforms`, and `profiles`.

#### driver
This section is optional, and is where default parameters are set. These are the available keys:

* `source_ami` - type: _string_, required

 AMI to build from, may be either a name or ID. It is recommended to use names, because many AMIs are built in multiple regions and the IDs change between regions while the names generally do not.

* `instance_type` - type: _string_, required

 EC2 [instance type](http://aws.amazon.com/ec2/instance-types/), e.g. `t2.micro`, `m3.medium`.

* `associate_public_ip_address` - type: _bool_, default: `true`

 If `true`, a public IP address will be assigned to the EC2 instance.

* `subnet` - type: _string_, optional

 Subnet to place EC2 instance into. As with `source_ami`, this may be a name or ID. If not given, the instance will be placed into a subnet in the default VPC.

* `security_groups` - type: _list_ of _string_, optional

 List of security groups to assign to the EC2 instance. May be names or IDs. If not given, the instance will be assigned the default security group of the default VPC.

* `connection` - type: _string_, one of `ssh` or `winrm`, default: `ssh`

 Connection type for Ansible to use.

* `connection_timeout` - type: _int_, default: `600`

 Number of seconds before connection to instance times out.

* `username` - type: _string_, default: `ec2-user`

 Username to connect over ssh or winrm.

* `become` - type: _boolean_, default: `true`

 If `true`, then Ansible will use sudo. This should be `false` if `connection` is `winrm`.

* `ami_name` - type: _string_, default: `'%(role)s.%(profile)s.%(platform)s.%(vtype)s.%(arch)s.%(version)s'`

 This is a Python formatted string to set the name of the image when using `bi image`.

 Variables that may be put into the formatted string are:

 * `role`: Name of Ansible role
 * `profile`: Name of profile used from `.boss.yml`
 * `platform`: Name of platform used from `.boss.yml`
 * `vtype`:  Virtualization type, e.g. `hvm`
 * `arch`:  Architecture, e.g. `x86_64`
 * `version`: Role version. Because Ansible does not provide a way to set a version in the role metadata, this is expected to be placed in a file `.role-version` in the root directory of the role. If the `.role-version` file is not found, then `version` will be the string `unset`.
 * `hv`:  Hypervisor, e.g. `xen`
 * Perhaps less useful but nonetheless available are any of the configuration values for the instance that may be found in the platform, such as `source_ami`, `instance_type`, `connection`, etc.

 Of course, `ami_name` may also be a string used verbatim without any interpolated variables in it.

* `port` - type: _int_, default: `22`

 Port for Ansible to use when connecting. If `connection` is `winrm`, then this should be `5985`.

* `block_device_mappings` - type: _list_ of _map_, default: `[]`

 Devices to be attached to the EC2 instance that will be part of a baked image.

 Each item in the list is a map as described in the `BlockDeviceMappings` property passed to the [boto3 create_instances operation](http://boto3.readthedocs.org/en/latest/reference/services/ec2.html#EC2.ServiceResource.create_instances). The only difference is that in `.boss.yml`, "CamelCase" properties should be converted to "snake_case".

 Example:

 ```
 block_device_mappings:
   - device_name: /dev/sdf
     ebs:
       volume_size: 100
       volume_type: gp2
       delete_on_termination: true
 ```

* `user_data` - type: _map_ or _string_, default: `''`

 This is the [user data](http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html) that will be passed into the EC2 instance. If the given type is a map, then it must have the key `file`, whose value is a valid path name to a file, whose contents will be put into the user data.

 Example:

 ```
 user_data:
   file: /path/to/user-data.txt
 ```

 If the type is a string, then it is passed verbatim as the user data for the instance.

 Example:

 ```
 user_data: |
   #!/bin/sh
   yum update
   yum upgrade -y
 ```

* `tags` - type: _map_ of _string_ to _string_, default: `{}`

 A map of key, value pairs of strings that the EC2 instance will be tagged with.

 Example:

 ```
 tags:
   Name: professor
   Description: A boss machine
 ```

#### platforms
This is the only section that is required. It contains a list of maps for each configured platform. Each map has one required key, `name`. Everything else is the same as for `driver`, but overrides anything that may be set in that section.

The most minimal `platforms` section just contains one platform with a name, with all other parameters inherited from `driver`. This assumes there is a `driver` section in the file with required parameters already set.

```
platforms:
  - name: ubuntu-15.10
```

In general, it makes the most sense for `source_ami` to go into `platforms` rather than `drivers`, as that is the one parameter that really determines the platform.

#### profiles
This section is also a list of maps, with each map requiring a `name` key. If this section is not provided, there will be an implicit `default` profile created. In addition to the name, there is an optional `extra_vars` key, which is an arbitrary map which will be passed to Ansible in its `--extra-vars` argument.

```
profiles:
  - name: default
    extra_vars:
      users:
        - joe
        - john
      packages:
        - nc
        - strace
        - tcpdump
```


# Rationale
All I want is to spin up an EC2 instance in AWS, run [Ansible](http://docs.ansible.com/ansible/index.html) on it, and bake it into an image if Ansible ran successfully. Packer does more and less than I want, Test Kitchen does more and less than I want, and both of them overlap in functionality.

### Comparison with Packer
Packer is a tool for creating VM and Docker images for a multitude of cloud providers and for local use.

`bossimage` creates VM images, but only for AWS.

### Comparison with Test Kitchen
Test Kitchen is a tool for testing Chef cookbooks, but can be used to test Ansible and other configuration management tools using third party plugins.

`bossimage` only runs Ansible, specifically Ansible [roles](http://docs.ansible.com/ansible/playbooks_roles.html), and only in "push" mode.

### Workflow with Test Kitchen and Packer
Using Test Kitchen and Packer together, my workflow went something like:

* Install Ansible
* Install Test Kitchen
* Install Test Kitchen EC2 driver
* Install Test Kitchen Ansible plugin
* Install Packer
* Develop, test, and iterate with Ansible and Test Kitchen
* Bake image with Packer

To test Ansible, I would create a role using `ansible-galaxy` and drop a `.kitchen.yml` configuration into the root of my role's directory. Then I could run `kitchen converge` to get an EC2 instance created in AWS, have Ansible installed on it, and then have my role run on the instance. Install Ansible on the instance, you say? That's right. Even though one of the primary appeals of Ansible is that it requires no installation on the target, the plugin for Test Kitchen installs Ansible on the target and then runs Ansible in local mode there. Although there are certainly use cases for running Ansible that way, I don't consider creating VM images to be one of the better ones.

Now for the second half of the process. If Test Kitchen successfully ran Ansible and my test suite, then I was ready to bake an image. What I would do is add an `ami/` directory to my roles, containing JSON configurations for Packer to use. I could put any number of JSON configurations in this directory, depending on what different flavors of image I might want baked. Then I would run Packer to create yet another EC2 instance, install Ansible on it, and run Ansible (in local mode). If Ansible ran successfully, Packer would bake it into an image. If Ansible failed at any point, Packer would delete the EC2 instance and I would have to start over again.

It should be obvious that this is less than optimal, as I needed two separate tools with their own configuration formats that both created EC2 instances and ran Ansible on them, each with different end goals. To try to make this process easier, I created a [Gradle](http://gradle.org/) build that would automatically generate tasks for each Packer configuration that went into the `ami/` directory, and also generated tasks for Test Kitchen, so we could run something like `gradle test ami clean` in a Jenkins job and get the whole process to run from a single command. While it did work, it was agonizingly slow.

All I could think to myself was: there has got to be a better way!

### Workflow with bossimage
Here is the new workflow:

* Install bossimage (Ansible is installed as a dependency)
* Develop, test, and iterate with Ansible and bossimage
* Bake image with bossimage
