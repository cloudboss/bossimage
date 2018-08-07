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
from contextlib import contextmanager
import json
import os
from random import choice, randrange, shuffle
import StringIO
import time
import unittest

from friend.net import random_ipv4
from friend.strings import random_alphanum, random_hex
import mock
import pyfakefs.fake_filesystem_unittest as fakefs_unittest
from voluptuous import Invalid
import yaml

import bossimage.core as bc


def make_inventory_string():
    args = ['rockafella.pem', 'ec2-user', None, '22', 'ssh']
    return '[build]\n{}\n[test]\n{}'.format(
        bc.inventory_entry(*['10.10.10.250']+args),
        bc.inventory_entry(*['10.10.10.251']+args),
    )


def make_an_inventory_string(keyfile, user, password, port, connection,
                             build_ip, test_ip):
    args = [keyfile, user, password, port, connection]
    build_args = [build_ip] + args
    test_args = [test_ip] + args
    return '[build]\n{}\n[test]\n{}'.format(
        bc.inventory_entry(*build_args),
        bc.inventory_entry(*test_args),
    )


def make_galaxy_args(requirements, verbosity):
    args = [
        'ansible-galaxy', 'install',
        '-r', requirements,
        '-p', '.boss/roles',
    ]
    if verbosity:
        args.append('-' + 'v' * verbosity)
    return args


def make_ansible_args(verbosity, inventory, playbook, extra_vars):
    args = ['ansible-playbook', '-i', inventory]
    if verbosity:
        args.append('-{}'.format('v' * verbosity))
    if extra_vars:
        args += ['--extra-vars', json.dumps(extra_vars)]
    args.append(playbook)
    return args


def mock_wait_for_connection(_a, _b, _c, _d, _e):
    time.sleep(0.2)


def mock_id(prefix, length):
    return '{}-{}'.format(prefix, random_hex(length))


def mock_ec2():
    m = mock.Mock()

    def create_key_pair(**kwargs):
        key_pair = mock.Mock()
        key_pair.key_material = random_alphanum(1000)
        return key_pair

    def create_image(**kwargs):
        image = mock.Mock()
        image.id = mock_id('ami', 8)
        image.state = 'available'
        return image

    def create_instance(**kwargs):
        instance = mock.Mock()
        instance.id = mock_id('i', 17)
        instance.wait_until_running = mock.Mock(
            side_effect=lambda: time.sleep(0.2)
        )
        instance.private_ip_address = str(random_ipv4())
        interfaces = kwargs.get('NetworkInterfaces', None)
        if interfaces and interfaces[0]['AssociatePublicIpAddress']:
            public_ip_address = str(random_ipv4(cidr='203.0.113.0/24'))
            instance.public_ip_address = public_ip_address
        else:
            instance.public_ip_address = None
        instance.create_image.side_effect = create_image
        instance.create_image.side_effect = create_image
        instance.architecture = 'x86_64'
        instance.hypervisor = 'xen'
        instance.virtualization_type = 'hvm'
        instance.password_data.return_value = {
            'PasswordData': random_alphanum(25)
        }
        return instance

    def create_instances(**kwargs):
        return [create_instance(**kwargs)]

    def images_filter(**kwargs):
        image = mock.Mock()
        image.id = mock_id('ami', 8)
        yield image

    m.create_key_pair.side_effect = create_key_pair
    m.Instance.side_effect = create_instance
    m.create_instances.side_effect = create_instances
    m.images.filter.side_effect = images_filter

    return m


class CoreTests(fakefs_unittest.TestCase):
    def setUp(self):
        self.setUpPyfakefs()

    def test_gen_keyname(self):
        keyname_len = len('bossimage-') + 10
        keynames = [bc.gen_keyname() for _ in range(0, randrange(100))]
        self.assertTrue(len(set(keynames)) == len(keynames))
        for keyname in keynames:
            self.assertTrue(len(keyname) == keyname_len)

    def test_user_data_file(self):
        user_date_file = random_alphanum(10)
        mock_user_data = random_alphanum(100)
        with open(user_date_file, 'w') as f:
            f.write(mock_user_data)

        config = {'user_data': {'file': user_date_file}}
        user_data = bc.user_data(config)
        self.assertEqual(user_data, mock_user_data)

    def test_user_data_string(self):
        config = {'user_data': random_alphanum(100)}
        user_data = bc.user_data(config)
        self.assertEqual(user_data, config['user_data'])

    def test_create_keypair(self):
        pass

    def test_tag_instance(self):
        pass

    def test_role_name_env(self):
        mock_role_name = random_alphanum(25)
        env = mock.Mock(return_value=mock_role_name)
        with mock.patch('os.getenv', env):
            role_name = bc.role_name()
        self.assertEqual(role_name, mock_role_name)
        env.assert_called_with('BI_ROLE_NAME')

    def test_role_name_dir(self):
        curdir = os.path.basename(os.getcwd())
        env = mock.Mock(return_value=None)
        with mock.patch('os.getenv', env):
            role_name = bc.role_name()
        self.assertEqual(role_name, curdir)
        env.assert_called_with('BI_ROLE_NAME')

    def test_role_version_env(self):
        env = mock.Mock(return_value=mock.sentinel.role_version)
        with mock.patch('os.getenv', env):
            role_version = bc.role_version()
        self.assertEqual(role_version, mock.sentinel.role_version)
        env.assert_called_with('BI_ROLE_VERSION')

    def test_role_version_file(self):
        mock_version = random_alphanum(10)
        with open('.role-version', 'w') as f:
            f.write(mock_version)
        env = mock.Mock(return_value=None)
        with mock.patch('os.getenv', env):
            role_version = bc.role_version()
        self.assertEqual(role_version, mock_version)
        env.assert_called_with('BI_ROLE_VERSION')

    def test_role_version_none(self):
        default_role_version = 'unset'
        env = mock.Mock(return_value=None)
        with mock.patch('os.getenv', env):
            role_version = bc.role_version()
        self.assertEqual(role_version, default_role_version)
        env.assert_called_with('BI_ROLE_VERSION')

    def test_parse_inventory(self):
        fdesc = StringIO.StringIO(make_inventory_string())
        expected_result = {
            'build': ' '.join([
                '10.10.10.250',
                'ansible_ssh_private_key_file=rockafella.pem',
                'ansible_user=ec2-user',
                'ansible_password=None',
                'ansible_port=22',
                'ansible_connection=ssh',
            ]),
            'test': ' '.join([
                '10.10.10.251',
                'ansible_ssh_private_key_file=rockafella.pem',
                'ansible_user=ec2-user',
                'ansible_password=None',
                'ansible_port=22',
                'ansible_connection=ssh',
            ])
        }
        actual_result = bc.parse_inventory(fdesc)
        self.assertEqual(actual_result, expected_result)

    def test_inventory_entry(self):
        gen_entry = bc.inventory_entry(
            '10.10.10.250', 'rockafella.pem', 'ec2-user', None, '22', 'ssh'
        )
        expected_entry = ' '.join([
            '10.10.10.250',
            'ansible_ssh_private_key_file=rockafella.pem',
            'ansible_user=ec2-user',
            'ansible_password=None',
            'ansible_port=22',
            'ansible_connection=ssh',
        ])
        self.assertEqual(gen_entry, expected_entry)

    def test_load_inventory(self):
        os.mkdir('.boss')
        instance = 'centos-7-default'
        inventory_file = '.boss/{}.inventory'.format(instance)
        args = ['rockafella.pem', 'ec2-user', None, '22', 'ssh']
        build_entry = bc.inventory_entry(*['10.10.10.250']+args)
        test_entry = bc.inventory_entry(*['10.10.10.251']+args)

        self.assertFalse(os.path.exists(inventory_file))

        with bc.load_inventory(instance) as inventory:
            self.assertEqual(inventory, {})
            inventory['build'] = build_entry
            inventory['test'] = test_entry

        self.assertTrue(os.path.exists(inventory_file))
        self.assertEqual(inventory['build'], build_entry)
        self.assertEqual(inventory['test'], test_entry)

        with bc.load_inventory(instance) as inventory:
            self.assertTrue('build' in inventory)
            del(inventory['build'])

        self.assertEqual(inventory, {'test': test_entry})

    def test_write_inventory(self):
        path = random_alphanum(10)
        fdesc = StringIO.StringIO(make_inventory_string())
        inventory = bc.parse_inventory(fdesc)

        self.assertFalse(os.path.exists(path))
        bc.write_inventory(path, inventory)
        self.assertTrue(os.path.exists(path))

        stat = os.stat(path)
        expected_mode = '0100600'
        self.assertEqual(oct(stat.st_mode), expected_mode)

        with open(path) as f:
            read_inventory = bc.parse_inventory(f)
        self.assertEqual(inventory, read_inventory)

    def test_write_playbook(self):
        path = random_alphanum(10)
        become = choice((True, False))
        role_name = random_alphanum(10)
        config = {'become': become}

        self.assertFalse(os.path.exists(path))

        env = mock.Mock(return_value=role_name)
        with mock.patch('os.getenv', env):
            bc.write_playbook(path, config)
        self.assertTrue(os.path.exists(path))
        env.assert_called_with('BI_ROLE_NAME')

        expected_playbook = [{
            'hosts': 'build',
            'become': become,
            'roles': [role_name]
        }]
        with open(path) as f:
            playbook = yaml.load(f)
        self.assertEqual(playbook, expected_playbook)

    def test_get_windows_password(self):
        pass


class Ec2Tests(unittest.TestCase):
    def setUp(self):
        self.ec2 = mock_ec2()
        self.state = {}
        self.inventory = {}
        self.config = {
            'instance_type': 't2.micro',
            'source_ami': mock_id('ami', 8),
            'ami_name': random_alphanum(25),
            'associate_public_ip_address': False,
            'block_device_mappings': [],
            'connection': 'ssh',
            'connection_timeout': 300,
            'username': random_alphanum(10),
            'port': choice(range(1, 65535)),
            'user_data': '',
            'playbook': 'test.yml',
            'extra_vars': {},
            'subnet': '',
            'security_groups': [],
            'iam_instance_profile': random_alphanum(10),
            'tags': {},
        }

    @contextmanager
    def load_state(self, _):
        yield self.state

    @contextmanager
    def load_inventory(self, _):
        yield self.inventory

    @mock.patch('os.chmod')
    def test_create_keypair(self, chmod):
        mocko = mock.mock_open()
        keyname = random_alphanum(10)
        keyfile = random_alphanum(10)
        with mock.patch('__builtin__.open', mocko):
            bc.create_keypair(self.ec2, keyname, keyfile)
        kp_args = {'KeyName': keyname}
        self.ec2.create_key_pair.assert_called_once_with(**kp_args)
        chmod.assert_called_once_with(keyfile, 0600)

    def test_create_instance(self):
        key_name = bc.gen_keyname()
        image_id = self.config['source_ami']
        public = self.config['associate_public_ip_address']
        kwargs = {
            'BlockDeviceMappings': [],
            'IamInstanceProfile': {
                'Name': self.config['iam_instance_profile']
            },
            'ImageId': self.config['source_ami'],
            'InstanceType': self.config['instance_type'],
            'KeyName': key_name,
            'MaxCount': 1,
            'MinCount': 1,
            'NetworkInterfaces': [{
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': public,
            }],
            'UserData': self.config['user_data'],
        }
        instance = bc.create_instance(self.ec2, self.config,
                                      image_id, key_name)
        instance.wait_until_running.assert_called()
        instance.reload.assert_called()
        self.assertTrue(instance.public_ip_address is None)
        self.ec2.create_instances.assert_called_with(**kwargs)
        self.ec2.create_tags.assert_not_called()

    def test_create_instance_tags_public(self):
        key_name = bc.gen_keyname()
        image_id = self.config['source_ami']
        name_tag = random_alphanum(20)
        self.config['tags'] = {'Name': name_tag}
        self.config['associate_public_ip_address'] = True
        public = self.config['associate_public_ip_address']
        kwargs = {
            'BlockDeviceMappings': [],
            'IamInstanceProfile': {
                'Name': self.config['iam_instance_profile']
            },
            'ImageId': self.config['source_ami'],
            'InstanceType': self.config['instance_type'],
            'KeyName': key_name,
            'MaxCount': 1,
            'MinCount': 1,
            'NetworkInterfaces': [{
                'DeviceIndex': 0,
                'AssociatePublicIpAddress': public,
            }],
            'UserData': self.config['user_data'],
        }
        instance = bc.create_instance(self.ec2, self.config,
                                      image_id, key_name)
        instance.wait_until_running.assert_called()
        instance.reload.assert_called()
        self.assertTrue(instance.public_ip_address)
        self.ec2.create_instances.assert_called_with(**kwargs)
        self.ec2.create_tags.assert_called_with(
            Resources=[instance.id],
            Tags=[{'Key': 'Name', 'Value': name_tag}],
        )

    def test_wait_for_image(self):
        pass

    def test_wait_for_password(self):
        pass

    @mock.patch('socket.create_connection', return_value=None)
    @mock.patch('subprocess.call', return_value=0)
    def test_wait_for_connection(self, proc, sock):
        end = time.time() + 2
        with mock.patch('time.sleep', return_value=None):
            bc.wait_for_connection(None, None, None, None, end)
        sock.assert_called()
        proc.assert_called()

    def test_wait_for_connection_timeout(self):
        ip = str(random_ipv4)
        port = 22
        end = time.time() - 1
        with self.assertRaises(bc.ConnectionTimeout):
            bc.wait_for_connection(ip, port, None, None, end)

    @mock.patch('bossimage.core.create_keypair', return_value=None)
    @mock.patch('bossimage.core.ensure_inventory', return_value=None)
    @mock.patch('bossimage.core.wait_for_connection',
                side_effect=mock_wait_for_connection)
    @mock.patch('bossimage.core.run_ansible', return_value=None)
    @mock.patch('os.path.exists', return_value=True)
    def test_make_build_new(self, path, ansible, wait, inv, kp):
        verbosity = 1
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            bc.make_build(self.ec2, random_alphanum(10),
                          self.config, verbosity)
        for f in path, ansible, wait, inv, kp, self.ec2.create_instances:
            self.assertTrue(f.called)

    @mock.patch('bossimage.core.create_keypair', return_value=None)
    @mock.patch('bossimage.core.ensure_inventory', return_value=None)
    @mock.patch('bossimage.core.wait_for_connection',
                side_effect=mock_wait_for_connection)
    @mock.patch('bossimage.core.run_ansible', return_value=None)
    @mock.patch('os.path.exists', return_value=True)
    def test_make_build_exists(self, path, ansible, wait, inv, kp):
        self.state = {
            'keyname': bc.gen_keyname(),
            'build': {
                'ip': str(random_ipv4()),
                'id': mock_id('i', 17),
            },
        }
        verbosity = 1
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            bc.make_build(self.ec2, random_alphanum(10),
                          self.config, verbosity)
        for f in kp, self.ec2.create_instances:
            f.assert_not_called()
        for f in path, ansible, wait, inv:
            f.assert_called()

    @mock.patch('bossimage.core.ensure_inventory', return_value=None)
    @mock.patch('bossimage.core.wait_for_connection',
                side_effect=mock_wait_for_connection)
    @mock.patch('bossimage.core.run_ansible', return_value=None)
    def test_make_test_new(self, ansible, wait, inv):
        self.state = {
            'keyname': bc.gen_keyname(),
            'build': {
                'ip': str(random_ipv4()),
                'id': mock_id('i', 17),
            },
            'image': {
                'id': mock_id('ami', 8),
            },
        }
        verbosity = 1
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            bc.make_test(self.ec2, random_alphanum(10),
                         self.config, verbosity)
        for f in ansible, wait, inv:
            f.assert_called()
        self.ec2.create_instances.assert_called()

    @mock.patch('bossimage.core.ensure_inventory', return_value=None)
    @mock.patch('bossimage.core.wait_for_connection',
                side_effect=mock_wait_for_connection)
    @mock.patch('bossimage.core.run_ansible', return_value=None)
    def test_make_test_exists(self, ansible, wait, inv):
        self.state = {
            'keyname': bc.gen_keyname(),
            'test': {
                'ip': str(random_ipv4()),
                'id': mock_id('i', 17),
            },
        }
        verbosity = 1
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            bc.make_test(self.ec2, random_alphanum(10),
                         self.config, verbosity)
        for f in ansible, wait, inv:
            f.assert_called()
        self.ec2.create_instances.assert_not_called()

    @mock.patch('bossimage.core.ensure_inventory', return_value=None)
    @mock.patch('bossimage.core.wait_for_connection',
                side_effect=mock_wait_for_connection)
    @mock.patch('bossimage.core.run_ansible', return_value=None)
    def test_make_test_no_image(self, ansible, wait, inv):
        verbosity = 1
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            with self.assertRaises(bc.StateError) as r:
                bc.make_test(self.ec2, random_alphanum(10),
                             self.config, verbosity)
        message = 'Cannot run `make test` before `make image`'
        self.assertEqual(r.exception.message, message)

    @mock.patch('bossimage.core.get_windows_password', return_value='winpw')
    @mock.patch('os.chmod', return_value=None)
    def test_ensure_inventory(self, _, get_password):
        keyfile = random_alphanum(25)
        expectations = (
            (
                'ssh',
                random_alphanum(10),
                mock_id('i', 17),
                random_ipv4(),
                None,
                choice(['build', 'test']),
            ),
            (
                'winrm',
                random_alphanum(10),
                mock_id('i', 17),
                random_ipv4(),
                'winpw',
                choice(['build', 'test']),
            ),
        )
        for cx, instance, ident, ip, password, phase in expectations:
            self.config['instance'] = instance
            self.config['connection'] = cx
            with mock.patch('__builtin__.open', mock.mock_open()) as m:
                bc.ensure_inventory(self.ec2, instance, phase,
                                    self.config, keyfile, ident, ip)
                self.assertEquals(get_password.called,
                                  True if cx == 'winrm' else False)
            handle = m()
            inventory = handle.write.call_args[0][0]
            expected_inventory = ''.join([
                '[{}]\n'.format(phase),
                '{} '.format(ip),
                'ansible_ssh_private_key_file={} '.format(keyfile),
                'ansible_user={} '.format(self.config['username']),
                'ansible_password={} '.format(password),
                'ansible_port={} '.format(self.config['port']),
                'ansible_connection={}'.format(cx),
            ])
            self.assertEqual(inventory, expected_inventory)

    @mock.patch('bossimage.core.inventory_entry', return_value=None)
    @mock.patch('bossimage.core.get_windows_password', return_value=None)
    @mock.patch('os.chmod', return_value=None)
    @mock.patch('os.path.exists', return_value=True)
    def test_ensure_inventory_exists(self, _p, _c, get_password, inv_entry):
        instance = random_alphanum(10)
        phase = choice(['build', 'test'])
        connection = choice(['ssh', 'winrm'])
        password = 'winpw' if connection == 'winrm' else None
        keyfile = random_alphanum(10)
        ip = str(random_ipv4())
        existing_inventory = ''.join([
            '[{}]\n'.format(phase),
            '{} '.format(ip),
            'ansible_ssh_private_key_file={} '.format(keyfile),
            'ansible_user={} '.format(self.config['username']),
            'ansible_password={} '.format(password),
            'ansible_port={} '.format(self.config['port']),
            'ansible_connection={}'.format(connection),
        ])
        mocko = mock.mock_open(read_data=existing_inventory)
        with mock.patch('__builtin__.open', mocko):
            bc.ensure_inventory(self.ec2, instance, phase,
                                self.config, keyfile, None, ip)
        self.ec2.Instance.assert_not_called()
        get_password.assert_not_called()
        inv_entry.assert_not_called()

    def test_run_ansible(self):
        for _ in range(0, 50):
            inventory = random_alphanum(10)
            verbosity = choice(range(0, 5))
            playbook = random_alphanum(10)
            req_exists = choice([True, False])
            requirements = random_alphanum(10)
            extra_vars = dict((random_alphanum(10), random_alphanum(10))
                              for _ in range(0, randrange(10)))

            with mock.patch('subprocess.Popen') as subproc:
                with mock.patch('os.path.exists', return_value=req_exists):
                    bc.run_ansible(verbosity, inventory, playbook,
                                   extra_vars, requirements)

            call_count = 2 if req_exists else 1
            self.assertEqual(subproc.call_count, call_count)

            if req_exists:
                galaxy_call_args = subproc.call_args_list[0]
                ansible_call_args = subproc.call_args_list[1]
                galaxy_args = make_galaxy_args(requirements, verbosity)
                self.assertEqual(galaxy_call_args[0][0], galaxy_args)
            else:
                ansible_call_args = subproc.call_args_list[0]

            env = ansible_call_args[1]['env']
            host_key_checking = env.get('ANSIBLE_HOST_KEY_CHECKING', None)
            roles_path = env.get('ANSIBLE_ROLES_PATH', None)
            ansible_args = make_ansible_args(verbosity, inventory,
                                             playbook, extra_vars)
            self.assertEqual(host_key_checking, 'False')
            self.assertEqual(roles_path, '.boss/roles:..')
            self.assertEqual(ansible_call_args[0][0], ansible_args)

    def test_make_image_new(self):
        instance = random_alphanum(10)
        self.state = {'build': {'id': mock_id('i', 17)}}
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            bc.make_image(self.ec2, instance, self.config, False)
        self.assertTrue(self.ec2.Instance.called)
        self.assertTrue('image' in self.state)

    def test_make_image_no_build(self):
        instance = random_alphanum(10)
        state_copy = self.state.copy()
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            with self.assertRaises(bc.StateError) as r:
                bc.make_image(self.ec2, instance, self.config, False)
        message = 'Cannot run `make image` before `make build`'
        self.assertEqual(r.exception.message, message)
        self.assertEqual(self.state, state_copy)

    def test_make_image_exists(self):
        instance = random_alphanum(10)
        self.state = {'image': {'id': mock_id('ami', 8)}}
        state_copy = self.state.copy()
        loader = 'bossimage.core.load_state'
        with mock.patch(loader, side_effect=self.load_state):
            bc.make_image(self.ec2, instance, self.config, False)
        self.assertFalse(self.ec2.Instance.called)
        self.assertEqual(self.state, state_copy)

    def test_clean_build(self):
        pass

    def test_clean_test(self):
        pass

    @mock.patch('bossimage.core.delete_files')
    def test_clean_instance_none(self, delete):
        state_copy = self.state.copy()
        instance = random_alphanum(10)
        phase = choice(['build', 'test'])
        state_loader = 'bossimage.core.load_state'
        inv_loader = 'bossimage.core.load_inventory'
        with mock.patch(state_loader, side_effect=self.load_state):
            with mock.patch(inv_loader, side_effect=self.load_inventory):
                bc.clean_instance(self.ec2, instance, phase)
        self.assertFalse(self.ec2.Instance.called)
        self.assertEqual(self.state, state_copy)
        self.assertFalse(delete.called)

    @mock.patch('bossimage.core.delete_files')
    @mock.patch('bossimage.core.delete_keypair')
    def test_clean_instance_one_phase(self, kp, files):
        keyname = random_alphanum(10)
        phase = choice(['build', 'test'])
        self.state = {phase: {'id': mock_id('i', 17)}, 'keyname': keyname}
        self.inventory = {phase: random_alphanum(25)}
        instance = random_alphanum(10)
        state_loader = 'bossimage.core.load_state'
        inv_loader = 'bossimage.core.load_inventory'
        with mock.patch(state_loader, side_effect=self.load_state):
            with mock.patch(inv_loader, side_effect=self.load_inventory):
                bc.clean_instance(self.ec2, instance, phase)
        self.assertFalse(phase in self.state)
        self.assertFalse(phase in self.inventory)
        self.assertTrue(self.ec2.Instance.called)
        self.assertTrue(kp.called)
        self.assertTrue(files.called)

    @mock.patch('bossimage.core.delete_files')
    @mock.patch('bossimage.core.delete_keypair')
    def test_clean_instance_both_phases(self, kp, files):
        keyname = random_alphanum(10)
        self.state = {
            'build': {'id': mock_id('i', 17)}, 'keyname': keyname,
            'test': {'id': mock_id('i', 17)}, 'keyname': keyname,
        }
        self.inventory = {
            'build': random_alphanum(25),
            'test': random_alphanum(25),
        }
        phases = ['build', 'test']
        shuffle(phases)
        phase, other_phase = phases
        instance = random_alphanum(10)
        state_loader = 'bossimage.core.load_state'
        inv_loader = 'bossimage.core.load_inventory'
        with mock.patch(state_loader, side_effect=self.load_state):
            with mock.patch(inv_loader, side_effect=self.load_inventory):
                bc.clean_instance(self.ec2, instance, phase)
        self.assertFalse(phase in self.state)
        self.assertFalse(phase in self.inventory)
        self.assertTrue(other_phase in self.state)
        self.assertTrue(other_phase in self.inventory)
        self.assertTrue(self.ec2.Instance.called)
        self.assertFalse(kp.called)
        self.assertFalse(files.called)

    def test_clean_image(self):
        pass

    def test_delete_keypair(self):
        pass

    def test_delete_files(self):
        pass

    def test_statuses(self):
        pass

    def test_login(self):
        pass

    def test_instance_files(self):
        pass

    def test_load_state(self):
        pass

    def test_resource_id_for(self):
        pass

    def test_ami_id_for(self):
        pass

    def test_sg_id_for(self):
        pass

    def test_subnet_id_for(self):
        pass

    def test_load_config_minimal(self):
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
        self.assertEqual(c, expected_transformation)

    def test_load_config_not_found(self):
        nosuchfile = random_alphanum(100)

        with self.assertRaises(bc.ConfigurationError) as r:
            bc.load_config(nosuchfile)

        self.assertEqual(
            r.exception.message,
            'Error loading {}: not found'.format(nosuchfile)
        )

    def test_load_config_syntax_error(self):
        filename = 'tests/resources/boss-badsyntax.yml'

        with self.assertRaises(bc.ConfigurationError) as r:
            bc.load_config(filename)

        expected = "expected token 'end of print statement', got ':', line 4"
        self.assertTrue(expected in r.exception.message)

    def test_load_config_validation_error1(self):
        filename = 'tests/resources/boss-bad1.yml'

        with self.assertRaises(bc.ConfigurationError) as r:
            bc.load_config(filename)

        expected = "required key not provided @ data['platforms'][0]['name']"
        self.assertTrue(expected in r.exception.message)

    def test_load_config_validation_error2(self):
        filename = 'tests/resources/boss-bad2.yml'

        with self.assertRaises(bc.ConfigurationError) as r:
            bc.load_config(filename)

        expected = "Error validating {}: expected bool"
        self.assertTrue(expected.format(filename) in r.exception.message)

    def test_load_config_env_vars(self):
        default_user = 'ec2-user'
        override_user = 'shisaboy'

        with mock.patch('os.environ', {}):
            c1 = bc.load_config('tests/resources/boss-env.yml')
        self.assertEqual(
            c1['amz-2015092-default']['build']['username'], default_user
        )

        with mock.patch('os.environ', {'BI_USERNAME': override_user}):
            c2 = bc.load_config('tests/resources/boss-env.yml')
        self.assertEqual(
            c2['amz-2015092-default']['build']['username'], override_user
        )

    def test_invalid(self):
        with self.assertRaises(Invalid) as r:
            thing_id = mock_id('thing', 8)
            raise bc.invalid('thing', thing_id)
        message = 'Invalid thing: {}'.format(thing_id)
        self.assertEqual(r.exception.message, message)

    def test_re_validator(self):
        pass

    def test_is_subnet_id(self):
        pass

    def test_is_snapshot_id(self):
        pass

    def test_is_virtual_name(self):
        pass

    def test_is_thing(self):
        expectations = (
            ('is_subnet_id', '', Invalid),
            ('is_subnet_id', mock_id('subnet', 1), Invalid),
            ('is_subnet_id', mock_id('fubnet', 8), Invalid),
            ('is_subnet_id', mock_id('subnet', 8), None),
            ('is_subnet_id', mock_id('subnet', 10), None),
            ('is_snapshot_id', '', Invalid),
            ('is_snapshot_id', mock_id('snap', 1), Invalid),
            ('is_snapshot_id', mock_id('fnap', 8), Invalid),
            ('is_snapshot_id', mock_id('snap', 8), None),
            ('is_snapshot_id', mock_id('snap', 10), None),
            ('is_virtual_name', '', Invalid),
            ('is_virtual_name', 'ephemeral-1', Invalid),
            ('is_virtual_name', 'ephemeral-10', Invalid),
            ('is_virtual_name', 'aphemeral8', Invalid),
            ('is_virtual_name', 'ephemeral8', None),
            ('is_virtual_name', 'ephemeral80', None),
        )
        for attr, test_id, error in expectations:
            func = getattr(bc, attr)
            if error:
                with self.assertRaises(error):
                    func(test_id)
            else:
                self.assertTrue(func(test_id))

    def test_is_volume_type(self):
        pass

    def test_validate(self):
        pass

    def test_transform_config(self):
        pass
