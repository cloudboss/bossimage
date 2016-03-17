from nose.tools import *
import bossimage.cli as cli

def test_merge_config():
    expected = {
        'amz-2015092-default': {
            'ami_name': '%(role)s-%(profile)s-%(version)s-%(platform)s',
            'associate_public_ip_address': True,
            'become': True,
            'block_device_mappings': [{
                'device_name': '/dev/sdf',
                'ebs': {
                    'delete_on_termination': True,
                    'volume_size': 100,
                    'volume_type': 'gp2'
                }
            }],
            'connection': 'ssh',
            'extra_vars': {},
            'instance_type': 't2.micro',
            'platform': 'amz-2015092',
            'port': 22,
            'profile': 'default',
            'security_groups': [],
            'source_ami': 'amzn-ami-hvm-2015.09.2.x86_64-gp2',
            'subnet': '',
            'username': 'ec2-user'
        },
        'win-2012r2-default': {
            'ami_name': 'ami-00000000',
            'associate_public_ip_address': True,
            'become': False,
            'block_device_mappings': [],
            'connection': 'winrm',
            'extra_vars': {},
            'instance_type': 'm3.medium',
            'platform': 'win-2012r2',
            'port': 5985,
            'profile': 'default',
            'security_groups': [],
            'source_ami': 'Windows_Server-2012-R2_RTM-English-64Bit-Base-2016.02.10',
            'subnet': '',
            'username': 'Administrator'
        }
    }

    c = cli.load_config('tests/resources/boss-good.yml')

    assert_equal(c, expected)
