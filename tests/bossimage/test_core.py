# Copyright 2017 Joseph Wright <joseph@cloudboss.co>
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
import os
import StringIO

import mock
from nose.tools import assert_equal, assert_raises, assert_true

import bossimage.core as bc
from tests.bossimage import probe, reset_probes, tempdir


def test_merge_config():
    expected = {
        'win-2012r2-default': {
            'platform': 'win-2012r2',
            'profile': 'default',
            'build': {
                'username': 'Administrator',
                'subnet': '',
                'source_ami': 'Windows_Server-2012-R2_RTM-English-64Bit-Base-2016.02.10', # noqa
                'tags': {},
                'extra_vars': {},
                'iam_instance_profile': '',
                'user_data': '',
                'instance_type': 'm3.medium',
                'connection': 'winrm',
                'profile': 'default',
                'platform': 'win-2012r2',
                'associate_public_ip_address': True,
                'become': False,
                'connection_timeout': 300,
                'port': 5985,
                'security_groups': [],
                'block_device_mappings': [],
            },
            'test': {
                'username': 'Administrator',
                'subnet': '',
                'tags': {},
                'iam_instance_profile': '',
                'user_data': '',
                'instance_type': 'm3.medium',
                'connection': 'winrm',
                'playbook': 'tests/test.yml',
                'associate_public_ip_address': True,
                'connection_timeout': 300,
                'port': 5985,
                'security_groups': [],
                'block_device_mappings': [],
            },
            'image': {
                'profile': 'default',
                'platform': 'win-2012r2',
                'ami_name': 'ami-00000000'
            },
        },
        'amz-2015092-default': {
            'platform': 'amz-2015092',
            'profile': 'default',
            'test': {
                'username': 'ec2-user',
                'subnet': '',
                'tags': {
                    'Name': 'hello',
                    'Description': 'A description'
                },
                'iam_instance_profile': '',
                'user_data': '',
                'instance_type': 't2.micro',
                'connection': 'ssh',
                'playbook': 'tests/test.yml',
                'associate_public_ip_address': True,
                'connection_timeout': 600,
                'port': 22,
                'security_groups': [],
                'block_device_mappings': [{
                    'ebs': {
                        'volume_size': 100,
                        'delete_on_termination': True,
                        'volume_type': 'gp2'
                    },
                    'device_name': '/dev/sdf'
                }]
            },
            'image': {
                'profile': 'default',
                'platform': 'amz-2015092',
                'ami_name': '%(role)s-%(profile)s-%(version)s-%(platform)s'
            },
            'build': {
                'username': 'ec2-user',
                'subnet': '',
                'source_ami': 'amzn-ami-hvm-2015.09.2.x86_64-gp2',
                'tags': {
                    'Name': 'hello',
                    'Description': 'A description'
                },
                'extra_vars': {},
                'iam_instance_profile': '',
                'user_data': '',
                'instance_type': 't2.micro',
                'connection': 'ssh',
                'profile': 'default',
                'platform': 'amz-2015092',
                'associate_public_ip_address': True,
                'become': True,
                'connection_timeout': 600,
                'port': 22,
                'security_groups': [],
                'block_device_mappings': [{
                    'ebs': {
                        'volume_size': 100,
                        'delete_on_termination': True,
                        'volume_type': 'gp2'
                    },
                    'device_name': '/dev/sdf'
                }]
            }
        }
    }

    c = bc.load_config('tests/resources/boss-good.yml')
    print(c)

    assert_equal(c, expected)


def test_userdata():
    c = bc.load_config('tests/resources/boss-userdata.yml')

    win_2012r2 = c['win-2012r2-default']['build']
    win_2012r2_user_data = '''<powershell>
winrm qc -q
winrm set winrm/config \'@{MaxTimeoutms="1800000"}\'
winrm set winrm/config/service \'@{AllowUnencrypted="true"}\'
winrm set winrm/config/service/auth \'@{Basic="true"}\'
Set-Item wsman:localhost\\client\\trustedhosts -value * -force
Get-NetFirewallProfile | Set-NetFirewallProfile -Enabled False\n</powershell>
'''
    assert_equal(bc.user_data(win_2012r2), win_2012r2_user_data)

    amz_2015092 = c['amz-2015092-default']['build']
    amz_2015092_user_data = '''#!/bin/sh
pip install ansible
'''
    assert_equal(bc.user_data(amz_2015092), amz_2015092_user_data)

    centos_6 = c['centos-6-default']['build']
    centos_6_user_data = '''#cloud-config
system_info:
  default_user:
    name: ec2-user
'''
    assert_equal(bc.user_data(centos_6), centos_6_user_data)

    centos_7 = c['centos-7-default']['build']
    assert_equal(bc.user_data(centos_7), '')


def test_load_config_minimal():
    c = bc.load_config('tests/resources/boss-minimal.yml')
    expected_transformation = {
        'amz-2015092-default': {
            'platform': 'amz-2015092',
            'profile': 'default',
            'build': {
                'associate_public_ip_address': True,
                'become': True,
                'block_device_mappings': [],
                'connection': 'ssh',
                'connection_timeout': 600,
                'extra_vars': {},
                'iam_instance_profile': '',
                'instance_type': 't2.micro',
                'platform': 'amz-2015092',
                'port': 22,
                'profile': 'default',
                'security_groups': [],
                'source_ami': 'amzn-ami-hvm-2015.09.2.x86_64-gp2',
                'subnet': '',
                'tags': {},
                'user_data': '',
                'username': 'ec2-user',
            },
            'test': {
                'associate_public_ip_address': True,
                'block_device_mappings': [],
                'connection': 'ssh',
                'connection_timeout': 600,
                'iam_instance_profile': '',
                'instance_type': 't2.micro',
                'playbook': 'tests/test.yml',
                'port': 22,
                'security_groups': [],
                'subnet': '',
                'tags': {},
                'user_data': '',
                'username': 'ec2-user',
            },
            'image': {
                'ami_name': '%(role)s.%(profile)s.%(platform)s.%(vtype)s.%(arch)s.%(version)s', # noqa
                'platform': 'amz-2015092',
                'profile': 'default',
            },
        },
    }
    assert_equal(c, expected_transformation)


def test_load_config_not_found():
    nosuchfile = bc.random_string(100)

    with assert_raises(bc.ConfigurationError) as r:
        bc.load_config(nosuchfile)

    assert_equal(
        r.exception.message,
        'Error loading {}: not found'.format(nosuchfile)
    )


def test_load_config_syntax_error():
    filename = 'tests/resources/boss-badsyntax.yml'

    with assert_raises(bc.ConfigurationError) as r:
        bc.load_config(filename)

    expected = "expected token 'end of print statement', got ':', line 4"
    assert_true(expected in r.exception.message)


def test_load_config_validation_error1():
    filename = 'tests/resources/boss-bad1.yml'

    with assert_raises(bc.ConfigurationError) as r:
        bc.load_config(filename)

    expected = "required key not provided @ data['platforms'][0]['name']"
    assert_true(expected in r.exception.message)


def test_load_config_validation_error2():
    filename = 'tests/resources/boss-bad2.yml'

    with assert_raises(bc.ConfigurationError) as r:
        bc.load_config(filename)

    expected = "Error validating {}: expected bool"
    assert_true(expected.format(filename) in r.exception.message)


def test_config_env_vars():
    default_user = 'ec2-user'
    override_user = 'shisaboy'

    with mock.patch('os.environ', {}):
        c1 = bc.load_config('tests/resources/boss-env.yml')
    assert_equal(c1['amz-2015092-default']['build']['username'], default_user)

    with mock.patch('os.environ', {'BI_USERNAME': override_user}):
        c2 = bc.load_config('tests/resources/boss-env.yml')
    assert_equal(c2['amz-2015092-default']['build']['username'], override_user)


def make_inventory_string():
    args = ['rockafella.pem', 'ec2-user', None, '22', 'ssh']
    return '''
    [build]
    {}
    [test]
    {}
    '''.format(
        bc.inventory_entry(*['10.10.10.250']+args),
        bc.inventory_entry(*['10.10.10.251']+args),
    )


def test_inventory_entry():
    gen_entry = bc.inventory_entry(
        '10.10.10.250', 'rockafella.pem', 'ec2-user', None, '22', 'ssh'
    )
    expected_entry = '10.10.10.250 ' \
                     'ansible_ssh_private_key_file=rockafella.pem ' \
                     'ansible_user=ec2-user ' \
                     'ansible_password=None ' \
                     'ansible_port=22 ' \
                     'ansible_connection=ssh'
    assert_equal(gen_entry, expected_entry)


def test_parse_inventory():
    fdesc = StringIO.StringIO(make_inventory_string())

    expected_result = {
        'build': '10.10.10.250 '
                 'ansible_ssh_private_key_file=rockafella.pem '
                 'ansible_user=ec2-user '
                 'ansible_password=None '
                 'ansible_port=22 '
                 'ansible_connection=ssh',
        'test': '10.10.10.251 '
                'ansible_ssh_private_key_file=rockafella.pem '
                'ansible_user=ec2-user '
                'ansible_password=None '
                'ansible_port=22 '
                'ansible_connection=ssh',
    }
    actual_result = bc.parse_inventory(fdesc)
    assert_equal(actual_result, expected_result)


def test_load_inventory():
    instance = 'centos-7-default'
    inventory_file = '{}/{}.inventory'.format(tempdir, instance)
    args = ['rockafella.pem', 'ec2-user', None, '22', 'ssh']
    build_entry = bc.inventory_entry(*['10.10.10.250']+args)
    test_entry = bc.inventory_entry(*['10.10.10.251']+args)

    assert(not os.path.exists(inventory_file))

    with bc.load_inventory(instance) as inventory:
        assert_equal(inventory, {})
        inventory['build'] = build_entry
        inventory['test'] = test_entry

    assert(os.path.exists(inventory_file))
    assert_equal(inventory['build'], build_entry)
    assert_equal(inventory['test'], test_entry)

    with bc.load_inventory(instance) as inventory:
        assert('build' in inventory)
        del(inventory['build'])

    assert_equal(inventory, {'test': test_entry})


def test_role_name():
    cwd = os.getcwd().split('/')[-1]
    assert_equal(bc.role_name(), cwd)

    env_role_name = 'mzwangendwa'

    os.environ['BI_ROLE_NAME'] = env_role_name
    assert_equal(bc.role_name(), env_role_name)

    del(os.environ['BI_ROLE_NAME'])


def test_role_version():
    cwd = os.getcwd()
    try:
        os.chdir(tempdir)

        assert_equal(bc.role_version(), 'unset')

        file_role_version = '100'
        with open('.role-version', 'w') as f:
            f.write(file_role_version)

        assert_equal(bc.role_version(), file_role_version)

        os.unlink('.role-version')

        env_role_version = '3.14'

        os.environ['BI_ROLE_VERSION'] = env_role_version
        assert_equal(bc.role_version(), env_role_version)
    finally:
        os.chdir(cwd)
        if 'BI_ROLE_VERSION' in os.environ:
            del(os.environ['BI_ROLE_VERSION'])


def test_create_instance_tags():
    config = bc.load_config('tests/resources/boss.yml')

    # win-2012r2 config has no tags
    reset_probes(['create_instances', 'create_tags'])
    bc.create_instance(
        config['win-2012r2-default']['build'], 'ami-00000000', 'mykey'
    )
    assert_equal(probe.called, ['create_instances'])

    # amz-2015092 config has tags
    reset_probes(['create_instances', 'create_tags'])
    bc.create_instance(
        config['amz-2015092-default']['build'], 'ami-00000000', 'mykey'
    )
    assert_equal(probe.called, ['create_instances', 'create_tags'])


def test_make_build():
    config = bc.load_config('tests/resources/boss.yml')
    instance = 'amz-2015092-default'

    reset_probes([
        'create_keypair', 'create_instance',
        'write_playbook', 'run_ansible'
    ])
    bc.make_build(instance, config[instance]['build'], 1)
    assert_equal(probe.called, [
        'create_keypair', 'create_instance', 'write_playbook', 'run_ansible'
    ])

    # Ensure that a second run only runs ansible without creating new resources
    reset_probes([
        'create_keypair', 'create_instance', 'write_playbook', 'run_ansible'
    ])
    bc.make_build(instance, config[instance]['build'], 1)
    assert_equal(probe.called, ['run_ansible'])


def test_make_test():
    config = bc.load_config('tests/resources/boss.yml')
    instance = 'amz-2015092-default'

    with assert_raises(bc.StateError) as r:
        bc.make_test(instance, config[instance]['test'], 1)
        assert_equal(
            r.exception.message,
            'Cannot run `make test` before `make image`'
        )

    bc.make_build(instance, config[instance]['build'], 1)

    # Should get another StateError because `make image` has not been run
    with assert_raises(bc.StateError) as r:
        bc.make_test(instance, config[instance]['test'], 1)
        assert_equal(
            r.exception.message,
            'Cannot run `make test` before `make image`'
        )

    bc.make_image(instance, config[instance]['image'], True)

    reset_probes(['create_instance', 'run_ansible'])
    bc.make_test(instance, config[instance]['test'], 1)
    assert_equal(probe.called, ['create_instance', 'run_ansible'])

    # As with `build`, a second run should create no new resources
    reset_probes(['create_instance', 'run_ansible'])
    bc.make_test(instance, config[instance]['test'], 1)
    assert_equal(probe.called, ['run_ansible'])

    for f in bc.instance_files(instance).values():
        os.unlink(f)


def test_make_image_wait():
    config = bc.load_config('tests/resources/boss.yml')
    instance = 'amz-2015092-default'
    wait = True

    bc.make_build(instance, config[instance]['build'], 1)

    reset_probes(['ec2_connect', 'wait_for_image'])
    bc.make_image(instance, config[instance]['image'], wait)
    assert_equal(probe.called, ['ec2_connect', 'wait_for_image'])

    reset_probes(['ec2_connect', 'wait_for_image'])
    bc.make_image(instance, config[instance]['image'], wait)
    assert_equal(probe.called, [])

    wait = False
    reset_probes(['ec2_connect', 'wait_for_image'])
    bc.make_image(instance, config[instance]['image'], wait)
    assert_equal(probe.called, [])

    for f in bc.instance_files(instance).values():
        os.unlink(f)


def test_make_image_no_wait():
    config = bc.load_config('tests/resources/boss.yml')
    instance = 'amz-2015092-default'
    wait = False

    bc.make_build(instance, config[instance]['build'], 1)

    reset_probes(['ec2_connect', 'wait_for_image'])
    bc.make_image(instance, config[instance]['image'], wait)
    assert_equal(probe.called, ['ec2_connect'])

    reset_probes(['ec2_connect', 'wait_for_image'])
    bc.make_image(instance, config[instance]['image'], wait)
    assert_equal(probe.called, [])
