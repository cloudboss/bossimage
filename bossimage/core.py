# Copyright 2017 Joseph Wright <rjosephwright@gmail.com>
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
from __future__ import print_function
import base64
import contextlib
import functools
import itertools
import json
import os
import random
import re
import socket
import string
import subprocess
import sys
import threading as t
import time
import tempfile
import yaml
import Queue

import boto3 as boto
import jinja2 as j
import pkg_resources as pr
import voluptuous as v


class ConnectionTimeout(Exception):
    pass


class ConfigurationError(Exception):
    pass


class StateError(Exception):
    pass


class ItemNotFound(Exception):
    pass


class Spinner(t.Thread):
    def __init__(self, waitable, state='to be available'):
        t.Thread.__init__(self)
        self.msg = 'Waiting for {} {} ...  '.format(waitable, state)
        self.running = False
        self.chars = itertools.cycle(r'-\|/')
        self.q = Queue.Queue()

    def __enter__(self):
        self.start()

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.running = False
        self.q.get()
        print('\bok')

    def run(self):
        print(self.msg, end='')
        self.running = True
        while self.running:
            print('\b{}'.format(next(self.chars)), end='')
            sys.stdout.flush()
            time.sleep(0.5)
        self.q.put(None)


def cached(func):
    cache = {}

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        key = func.__name__ + str(sorted(args)) + str(sorted(kwargs.items()))
        if key not in cache:
            cache[key] = func(*args, **kwargs)
        return cache[key]
    return wrapper


@cached
def ec2_connect():
    session = boto.Session()
    return session.resource('ec2')


def snake_to_camel(s):
    return ''.join(part[0].capitalize() + part[1:] for part in s.split('_'))


def camelify(spec):
    if type(spec) == list:
        return [camelify(m) for m in spec]
    elif type(spec) == dict:
        return {snake_to_camel(k): camelify(v) for k, v in spec.items()}
    else:
        return spec


def random_string(length=10):
    letters = string.ascii_letters + string.digits
    end = len(letters)
    return ''.join(letters[random.randrange(0, end)] for _ in range(length))


def gen_keyname():
    return 'bossimage-' + random_string()


def user_data(config):
    if type(config['user_data']) == dict:
        with open(config['user_data']['file']) as f:
            return f.read()

    if not config['user_data'] and config['connection'] == 'winrm':
        ud = pr.resource_string('bossimage', 'win-userdata.txt')
    else:
        ud = config['user_data']
    return ud


def create_keypair(keyname, keyfile):
    kp = ec2_connect().create_key_pair(KeyName=keyname)
    print('Created keypair {}'.format(keyname))

    with open(keyfile, 'w') as f:
        f.write(kp.key_material)
    os.chmod(keyfile, 0600)


def tag_instance(tags, instance):
    ec2_connect().create_tags(
        Resources=[instance.id],
        Tags=[{'Key': k, 'Value': v} for k, v in tags.items()]
    )
    print('Tagged instance with {}'.format(tags))


def create_instance(config, files, keyname):
    instance_params = dict(
        ImageId=ami_id_for(config['source_ami']),
        InstanceType=config['instance_type'],
        MinCount=1,
        MaxCount=1,
        KeyName=keyname,
        NetworkInterfaces=[dict(
            DeviceIndex=0,
            AssociatePublicIpAddress=config['associate_public_ip_address'],
        )],
        BlockDeviceMappings=camelify(config['block_device_mappings']),
        UserData=user_data(config),
    )
    if config['subnet']:
        subnet_id = subnet_id_for(config['subnet'])
        instance_params['NetworkInterfaces'][0]['SubnetId'] = subnet_id
    if config['security_groups']:
        sg_ids = [sg_id_for(name) for name in config['security_groups']]
        instance_params['NetworkInterfaces'][0]['Groups'] = sg_ids

    (instance,) = ec2_connect().create_instances(**instance_params)
    print('Created instance {}'.format(instance.id))

    with Spinner('instance', 'to be running'):
        instance.wait_until_running()

    if config['tags']:
        tag_instance(config['tags'], instance)

    instance.reload()
    return instance


def role_name():
    env_role = os.getenv('BI_ROLE_NAME')
    return env_role if env_role else os.path.basename(os.getcwd())


def role_version():
    def file_version():
        if os.path.exists('.role-version'):
            with open('.role-version') as f:
                return f.read().strip()
        else:
            return 'unset'
    env_version = os.getenv('BI_ROLE_VERSION')
    return env_version if env_version else file_version()


def decrypt_password(password_file, keyfile):
    openssl = subprocess.Popen([
        'openssl', 'rsautl', '-decrypt',
        '-in', password_file,
        '-inkey', keyfile,
    ], stdout=subprocess.PIPE)
    password, _ = openssl.communicate()
    return password


def parse_inventory(fdesc):
    inventory = {}
    section = None
    for line in fdesc.readlines():
        whitespace_match = re.match('^\s*$', line)
        if whitespace_match:
            continue

        section_match = re.match('^\s*\[(?P<section>\w+)\]\s*', line)
        if section_match:
            section = section_match.groupdict()['section']
            continue

        inventory[section] = line.strip()
    return inventory


def inventory_entry(ip, keyfile, username, password, port, connection):
    entry = '{} ' \
        'ansible_ssh_private_key_file={} ' \
        'ansible_user={} ' \
        'ansible_password={} ' \
        'ansible_port={} ' \
        'ansible_connection={}'.format(
            ip, keyfile, username, password, port, connection
        )
    return entry


@contextlib.contextmanager
def load_inventory(instance):
    files = instance_files(instance)
    if os.path.exists(files['inventory']):
        with open(files['inventory']) as f:
            inventory = parse_inventory(f)
    else:
        inventory = dict()
    yield inventory
    write_inventory(files['inventory'], inventory)


def write_inventory(path, inventory):
    template = '[{}]\n{}'
    inventory_string = '\n'.join(template.format(grp, host)
                                 for grp, host in inventory.items())
    with open(path, 'w') as f:
        f.write(inventory_string)
    os.chmod(path, 0600)


def write_playbook(playbook, config):
    with open(playbook, 'w') as f:
        f.write(yaml.safe_dump([dict(
            hosts='build',
            become=config['become'],
            roles=[role_name()],
        )]))


def write_files(instance, files, ec2_instance, keyname, config, password):
    if config['associate_public_ip_address']:
        ip_address = ec2_instance.public_ip_address
    else:
        ip_address = ec2_instance.private_ip_address

    files = instance_files(instance)

    with open(files['state'], 'w') as f:
        f.write(yaml.safe_dump(dict(
            keyname=keyname,
            build=dict(
                id=ec2_instance.id,
                ip=ip_address
            )
        )))

    with load_inventory(instance) as inventory:
        inventory['build'] = inventory_entry(
            ip_address, files['keyfile'], config['username'],
            password, config['port'], config['connection']
        )

    write_playbook(files['playbook'], config)


def get_windows_password(ec2_instance, keyfile):
    with Spinner('password'):
        encrypted_password = wait_for_password(ec2_instance)
    password_file = tempfile.mktemp(dir='.boss')
    with open(password_file, 'w') as f:
        f.write(base64.decodestring(encrypted_password))
    password = decrypt_password(password_file, keyfile)
    os.unlink(password_file)
    return password


def create_instance_v2(config, image_id, keyname):
    instance_params = dict(
        ImageId=image_id,
        InstanceType=config['instance_type'],
        MinCount=1,
        MaxCount=1,
        KeyName=keyname,
        NetworkInterfaces=[dict(
            DeviceIndex=0,
            AssociatePublicIpAddress=config['associate_public_ip_address'],
        )],
        BlockDeviceMappings=camelify(config['block_device_mappings']),
        UserData=user_data(config),
    )
    if config['subnet']:
        subnet_id = subnet_id_for(config['subnet'])
        instance_params['NetworkInterfaces'][0]['SubnetId'] = subnet_id
    if config['security_groups']:
        sg_ids = [sg_id_for(name) for name in config['security_groups']]
        instance_params['NetworkInterfaces'][0]['Groups'] = sg_ids
    if config['iam_instance_profile']:
        instance_params['IamInstanceProfile'] = {
            'Name': config['iam_instance_profile']
        }

    (ec2_instance,) = ec2_connect().create_instances(**instance_params)
    print('Created instance {}'.format(ec2_instance.id))

    with Spinner('instance', 'to be running'):
        ec2_instance.wait_until_running()

    if config['tags']:
        tag_instance(config['tags'], ec2_instance)

    ec2_instance.reload()
    return ec2_instance


def load_or_create_instance(config):
    instance = '{}-{}'.format(config['platform'], config['profile'])
    files = instance_files(instance)

    if not os.path.exists(files['state']):
        keyname = gen_keyname()

        create_keypair(keyname, files['keyfile'])
        ec2_instance = create_instance(config, files, keyname)

        if config['connection'] == 'winrm':
            encrypted_password = wait_for_password(ec2_instance)
            password_file = tempfile.mktemp(dir='.boss')
            with open(password_file, 'w') as f:
                f.write(base64.decodestring(encrypted_password))
            password = decrypt_password(password_file, files['keyfile'])
            os.unlink(password_file)
        else:
            password = None

        write_files(instance, files, ec2_instance, keyname, config, password)

    with open(files['state']) as f:
        return yaml.load(f)


def wait_for_image(image):
    while(True):
        image.reload()
        if image.state == 'available':
            break
        else:
            time.sleep(15)


def wait_for_password(ec2_instance):
    while True:
        ec2_instance.reload()
        pd = ec2_instance.password_data()
        if pd['PasswordData']:
            return pd['PasswordData']
        else:
            time.sleep(15)


def wait_for_connection(addr, port, inventory, group, connection, end):
    env = os.environ.copy()
    env.update(dict(ANSIBLE_HOST_KEY_CHECKING='False'))

    while(True):
        if time.time() > end:
            message = 'Timeout while connecting to {}:{}'.format(addr, port)
            raise ConnectionTimeout(message)
        try:
            # First check if port is open.
            socket.create_connection((addr, port), 1)

            # We didn't raise an exception, so port is open.
            # Now check if we can actually log in.
            with open('/dev/null', 'wb') as devnull:
                ret = subprocess.call([
                    'ansible', group,
                    '-i', inventory, '-m', 'raw', '-a', 'exit'
                ], stderr=devnull, stdout=devnull, env=env)
                if ret == 0:
                    break
                else:
                    raise
        except:
            time.sleep(15)


def run(instance, config, verbosity):
    if not os.path.exists('.boss'):
        os.mkdir('.boss')

    files = instance_files(instance)

    instance_info = load_or_create_instance(config)

    ip = instance_info['build']['ip']
    port = config['port']
    end = time.time() + config['connection_timeout']
    with Spinner('connection to {}:{}'.format(ip, port)):
        wait_for_connection(
            ip, port, files['inventory'], 'build', config['connection'], end)

    env = os.environ.copy()

    roles_path = '.boss/roles'

    env.update(dict(ANSIBLE_ROLES_PATH='{}:..'.format(roles_path)))

    if os.path.exists('requirements.yml'):
        ansible_galaxy_args = [
            'ansible-galaxy', 'install',
            '-r', 'requirements.yml',
            '-p', roles_path,
        ]
        if verbosity:
            ansible_galaxy_args.append('-' + 'v' * verbosity)
        ansible_galaxy = subprocess.Popen(ansible_galaxy_args, env=env)
        ansible_galaxy.wait()

    env.update(dict(ANSIBLE_HOST_KEY_CHECKING='False'))

    ansible_playbook_args = ['ansible-playbook', '-i', files['inventory']]
    if verbosity:
        ansible_playbook_args.append('-' + 'v' * verbosity)
    if config['extra_vars']:
        ansible_playbook_args += [
            '--extra-vars', json.dumps(config['extra_vars'])
        ]
    ansible_playbook_args.append(files['playbook'])
    ansible_playbook = subprocess.Popen(ansible_playbook_args, env=env)
    return ansible_playbook.wait()


def make_build(instance, config, verbosity):
    if not os.path.exists('.boss'):
        os.mkdir('.boss')

    files = instance_files(instance)
    keyfile = files['keyfile']

    with load_state(instance) as state:
        if 'keyname' not in state:
            keyname = gen_keyname()
            create_keypair(keyname, keyfile)
            state['keyname'] = keyname

    with load_state(instance) as state:
        if 'build' not in state:
            ec2_instance = create_instance_v2(
                config, ami_id_for(config['source_ami']), state['keyname']
            )
            if config['associate_public_ip_address']:
                ip_address = ec2_instance.public_ip_address
            else:
                ip_address = ec2_instance.private_ip_address
            state['build'] = {
                'id': ec2_instance.id,
                'ip': ip_address,
            }

    ensure_inventory(
        instance, 'build', config, keyfile,
        state['build']['id'], state['build']['ip'])

    with Spinner('connection to {}:{}'.format(
            state['build']['ip'], config['port'])):
        wait_for_connection(
            state['build']['ip'], config['port'], files['inventory'], 'build',
            config['connection'], time.time() + config['connection_timeout']
        )

    if not os.path.exists(files['playbook']):
        write_playbook(files['playbook'], config)

    return run_ansible(verbosity, files['inventory'], files['playbook'],
                       config['extra_vars'], 'requirements.yml')


def make_test(instance, config, verbosity):
    with load_state(instance) as state:
        if 'test' not in state and 'image' not in state:
            raise StateError('Cannot run `make test` before `make image`')

        if 'test' not in state:
            ec2_instance = create_instance_v2(
                config, state['image']['id'], state['keyname']
            )
            if config['associate_public_ip_address']:
                ip_address = ec2_instance.public_ip_address
            else:
                ip_address = ec2_instance.private_ip_address
            state['test'] = {
                'id': ec2_instance.id,
                'ip': ip_address,
            }

    files = instance_files(instance)

    ensure_inventory(
        instance, 'test', config, files['keyfile'],
        state['test']['id'], state['test']['ip'])

    with Spinner('connection to {}:{}'.format(
            state['test']['ip'], config['port'])):
        wait_for_connection(
            state['test']['ip'], config['port'], files['inventory'], 'test',
            config['connection'], time.time() + config['connection_timeout']
        )

    return run_ansible(verbosity, files['inventory'], config['playbook'], {},
                       'tests/requirements.yml')


def ensure_inventory(instance, phase, config, keyfile, ident, ip):
    with load_inventory(instance) as inventory:
        if phase not in inventory:
            ec2_instance = ec2_connect().Instance(id=ident)
            if config['connection'] == 'winrm':
                password = get_windows_password(ec2_instance, keyfile)
            else:
                password = None

            inventory[phase] = inventory_entry(
                ip, keyfile, config['username'],
                password, config['port'], config['connection']
            )


def run_ansible(verbosity, inventory, playbook, extra_vars, requirements):
    roles_path = '.boss/roles'

    env = os.environ.copy()
    env.update(dict(
        ANSIBLE_ROLES_PATH='{}:..'.format(roles_path),
        ANSIBLE_HOST_KEY_CHECKING='False',
    ))

    if os.path.exists(requirements):
        ansible_galaxy_args = [
            'ansible-galaxy', 'install',
            '-r', 'requirements.yml',
            '-p', roles_path,
        ]
        if verbosity:
            ansible_galaxy_args.append('-' + 'v' * verbosity)
        ansible_galaxy = subprocess.Popen(ansible_galaxy_args, env=env)
        ansible_galaxy.wait()

    ansible_playbook_args = ['ansible-playbook', '-i', inventory]
    if verbosity:
        ansible_playbook_args.append('-' + 'v' * verbosity)
    if extra_vars:
        ansible_playbook_args += ['--extra-vars', json.dumps(extra_vars)]
    ansible_playbook_args.append(playbook)
    ansible_playbook = subprocess.Popen(ansible_playbook_args, env=env)
    return ansible_playbook.wait()


def make_image(instance, config, wait):
    with load_state(instance) as state:
        if 'image' in state:
            return

        if 'build' not in state:
            raise StateError('Cannot run `make image` before `make build`')
        ec2 = ec2_connect()
        ec2_instance = ec2.Instance(id=state['build']['id'])
        ec2_instance.load()

        config.update({
            'role': role_name(),
            'version': role_version(),
            'arch': ec2_instance.architecture,
            'hv': ec2_instance.hypervisor,
            'vtype': ec2_instance.virtualization_type,
        })

        image_name = config['ami_name'] % config
        image = ec2_instance.create_image(Name=image_name)
        print('Created image {} with name {}'.format(image.id, image_name))

        state['image'] = {'id': image.id}

    if wait:
        with Spinner('image'):
            wait_for_image(image)


def clean_build(instance):
    clean_instance(instance, 'build')


def clean_test(instance):
    clean_instance(instance, 'test')


def clean_instance(instance, phase):
    with load_state(instance) as state:
        if phase not in state:
            print('No {} instance found for {}'.format(phase, instance))
            return

        ec2_instance = ec2_connect().Instance(id=state[phase]['id'])
        ec2_instance.terminate()
        print('Deleted instance {}'.format(ec2_instance.id))
        del(state[phase])

    with load_inventory(instance) as inventory:
        del(inventory[phase])

    if 'build' not in state and 'test' not in state:
        with load_state(instance) as state:
            delete_keypair(state)

    if 'build' not in state and 'image' not in state and 'test' not in state:
        delete_files(instance_files(instance))


def clean_image(instance):
    with load_state(instance) as state:
        if 'image' not in state:
            print('No image found for {}'.format(instance))
            return

        (image,) = ec2_connect().images.filter(ImageIds=[state['image']['id']])
        image.deregister()
        print('Deregistered image {}'.format(state['image']['id']))
        del(state['image'])

    if 'build' not in state and 'test' not in state:
        delete_files(instance_files(instance))


def delete_keypair(state):
    kp = ec2_connect().KeyPair(name=state['keyname'])
    kp.delete()
    print('Deleted keypair {}'.format(kp.name))
    del(state['keyname'])


def delete_files(files):
    for f in files.values():
        try:
            os.unlink(f)
        except OSError:
            print('Error removing {}, skipping'.format(f))


def statuses(config):
    def exists(instance):
        return os.path.exists('.boss/{}-state.yml'.format(instance))
    return [(instance, exists(instance)) for instance in config.keys()]


def login(instance, config, phase='build'):
    files = instance_files(instance)

    with open(files['state']) as f:
        state = yaml.load(f)

    ssh = subprocess.Popen([
        'ssh', '-i', files['keyfile'],
        '-l', config['username'], state[phase]['ip']
    ])
    ssh.wait()


def instance_files(instance):
    return dict(
        state='.boss/{}-state.yml'.format(instance),
        keyfile='.boss/{}.pem'.format(instance),
        inventory='.boss/{}.inventory'.format(instance),
        playbook='.boss/{}-playbook.yml'.format(instance),
    )


@contextlib.contextmanager
def load_state(instance):
    files = instance_files(instance)
    if not os.path.exists(files['state']):
        state = dict()
    else:
        with open(files['state']) as f:
            state = yaml.safe_load(f)
    yield state
    with open(files['state'], 'w') as f:
        f.write(yaml.safe_dump(state))


def resource_id_for(collection, collection_desc, name, prefix, flt):
    if name.startswith(prefix):
        return name
    item = list(collection.filter(Filters=[flt]))
    if item:
        return item[0].id
    else:
        desc = '{} "{}"'.format(collection_desc, name)
        raise ItemNotFound(desc)


def ami_id_for(name):
    ec2 = ec2_connect()
    return resource_id_for(
        ec2.images, 'image', name, 'ami-',
        {'Name': 'name', 'Values': [name]}
    )


def sg_id_for(name):
    ec2 = ec2_connect()
    return resource_id_for(
        ec2.security_groups, 'security group', name, 'sg-',
        {'Name': 'group-name', 'Values': [name]}
    )


def subnet_id_for(name):
    ec2 = ec2_connect()
    return resource_id_for(
        ec2.subnets, 'subnet ', name, 'subnet-',
        {'Name': 'tag:Name', 'Values': [name]}
    )


def load_config(path='.boss.yml'):
    loader = j.FileSystemLoader('.')
    pre_validate = pre_merge_schema()
    post_validate = post_merge_schema()
    try:
        template = loader.load(j.Environment(), path, os.environ)
        yml = template.render()
        c = pre_validate(yaml.load(yml))
        if 'driver' in c:
            c['defaults'] = c['driver']
            del(c['driver'])
        if 'defaults' not in c:
            c['defaults'] = {}
        return post_validate(merge_config(c))
    except j.TemplateNotFound:
        error = 'Error loading {}: not found'.format(path)
        raise ConfigurationError(error)
    except j.TemplateSyntaxError as e:
        error = 'Error loading {}: {}, line {}'.format(path, e, e.lineno)
        raise ConfigurationError(error)
    except IOError as e:
        error = 'Error loading {}: {}'.format(path, e.strerror)
        raise ConfigurationError(error)
    except v.Invalid as e:
        error = 'Error validating {}: {}'.format(path, e)
        raise ConfigurationError(error)


def load_config_v2(path='.boss.yml'):
    loader = j.FileSystemLoader('.')
    try:
        template = loader.load(j.Environment(), path, os.environ)
        yml = template.render()
        doc = yaml.load(yml)
        return transform_config(doc)
    except j.TemplateNotFound:
        error = 'Error loading {}: not found'.format(path)
        raise ConfigurationError(error)
    except j.TemplateSyntaxError as e:
        error = 'Error loading {}: {}, line {}'.format(path, e, e.lineno)
        raise ConfigurationError(error)
    except IOError as e:
        error = 'Error loading {}: {}'.format(path, e.strerror)
        raise ConfigurationError(error)
    except v.Invalid as e:
        error = 'Error validating {}: {}'.format(path, e)
        raise ConfigurationError(error)


def merge_config(c):
    merged = {}
    for platform in c['platforms']:
        for profile in c['profiles']:
            instance = '{}-{}'.format(platform['name'], profile['name'])
            merged[instance] = {
                k: v for k, v in platform.items() if k != 'name'
            }
            merged[instance]['platform'] = platform['name']
            merged[instance].update({
                k: v for k, v in c['defaults'].items() if k not in platform
            })
            merged[instance].update({
                k: v for k, v in profile.items() if k != 'name'
            })
            merged[instance]['profile'] = profile['name']
    return merged


def invalid(kind, item):
    return v.Invalid('Invalid {}: {}'.format(kind, item))


def re_validator(pat, s, kind):
    if not re.match(pat, s):
        raise invalid(kind, s)
    return s


def is_subnet_id(s):
    return re_validator(r'subnet-[0-9a-f]{8}', s, 'subnet_id')


def is_snapshot_id(s):
    return re_validator(r'snap-[0-9a-f]{8}', s, 'snapshot_id')


def is_virtual_name(s):
    return re_validator(r'ephemeral\d+', s, 'virtual_name')


def is_volume_type(s):
    if s not in ('gp2', 'io1', 'standard'):
        raise invalid('volume_type', s)
    return s


def pre_merge_schema():
    default_profiles = [{
        'name': 'default',
        'extra_vars': {}
    }]
    return v.Schema({
        v.Optional('driver', default={}): {v.Extra: object},
        v.Required('platforms'): [{
            v.Required('name'): str,
        }],
        v.Optional('profiles', default=default_profiles): [{
            v.Required('name'): str,
        }],
    }, extra=v.ALLOW_EXTRA)


def validate_v2(doc):
    base = {
        v.Optional('instance_type'): str,
        v.Optional('username'): str,
        v.Optional('connection'): v.Or('ssh', 'winrm'),
        v.Optional('connection_timeout'): int,
        v.Optional('port'): int,
        v.Optional('associate_public_ip_address'): bool,
        v.Optional('subnet'): str,
        v.Optional('security_groups'): [str],
        v.Optional('iam_instance_profile'): str,
        v.Optional('tags'): {str: str},
        v.Optional('user_data'): v.Or(
            str,
            {'file': str},
        ),
        v.Optional('block_device_mappings'): [{
            v.Required('device_name'): str,
            'ebs': {
                'volume_size': int,
                'volume_type': is_volume_type,
                'delete_on_termination': bool,
                'encrypted': bool,
                'iops': int,
                'snapshot_id': is_snapshot_id,
            },
            'no_device': str,
            'virtual_name': is_virtual_name,
        }],
    }
    defaults = {
        v.Optional('instance_type', default='t2.micro'): str,
        v.Optional('username', default='ec2-user'): str,
        v.Optional('connection', default='ssh'): v.Or('ssh', 'winrm'),
        v.Optional('connection_timeout', default=600): int,
        v.Optional('port', default=22): int,
        v.Optional('associate_public_ip_address', default=True): bool,
        v.Optional('subnet', default=''): str,
        v.Optional('security_groups', default=[]): [str],
        v.Optional('iam_instance_profile', default=''): str,
        v.Optional('tags', default={}): {str: str},
        v.Optional('user_data', default=''): v.Or(
            str,
            {'file': str},
        ),
        v.Optional('block_device_mappings', default=[]): [{
            v.Required('device_name'): str,
            'ebs': {
                'volume_size': int,
                'volume_type': is_volume_type,
                'delete_on_termination': bool,
                'encrypted': bool,
                'iops': int,
                'snapshot_id': is_snapshot_id,
            },
            'no_device': str,
            'virtual_name': is_virtual_name,
        }],
    }
    build = base.copy()
    build.update({
        v.Required('source_ami'): str,
        v.Optional('become', default=True): bool,
        v.Optional('extra_vars', default={}): dict,
    })
    image = {
        v.Optional('ami_name'): str,
    }
    test = base.copy()
    test.update({
        v.Optional('playbook', default='tests/test.yml'): str
    })
    platform = base.copy()
    ami_name = '%(role)s.%(profile)s.%(platform)s.%(vtype)s.%(arch)s.%(version)s'
    platform.update({
        v.Required('name'): str,
        v.Required('build'): build,
        v.Optional('image', default={'ami_name': ami_name}): image,
        v.Optional('test', default={'playbook': 'tests/test.yml'}): test,
    })
    profile = {
        v.Required('name'): str,
        v.Optional('extra_vars', default={}): dict
    }
    return v.Schema({
        v.Optional('defaults', default={}): defaults,
        v.Required('platforms'): [platform],
        v.Optional('profiles', default=[{
            'name': 'default', 'extra_vars': {}
        }]): [profile],
    })(doc)


def transform_config(doc):
    doc.setdefault('defaults', {})
    validated = validate_v2(doc)
    transformed = {}
    excluded_items = ('name', 'build', 'image', 'test')
    for platform in validated['platforms']:
        for profile in validated['profiles']:
            instance = '{}-{}'.format(platform['name'], profile['name'])
            transformed[instance] = {}

            transformed[instance]['build'] = validated['defaults'].copy()
            transformed[instance]['build'].update({
                k: v for k, v in platform.items() if k not in excluded_items
            })
            transformed[instance]['build'].update(platform['build'].copy())
            transformed[instance]['build'].update({
                'extra_vars':  profile['extra_vars'].copy(),
                'platform': platform['name'],
                'profile': profile['name'],
            })

            transformed[instance]['image'] = platform['image'].copy()
            transformed[instance]['image'].update({
                'platform': platform['name'],
                'profile': profile['name'],
            })

            transformed[instance]['test'] = validated['defaults'].copy()
            transformed[instance]['test'].update({
                k: v for k, v in platform.items() if k not in excluded_items
            })
            transformed[instance]['test'].update(platform['test'].copy())

            transformed[instance]['platform'] = platform['name']
            transformed[instance]['profile'] = profile['name']
    return transformed


def post_merge_schema():
    ami_name = '%(role)s.%(profile)s.%(platform)s.%(vtype)s.%(arch)s.%(version)s'
    return v.Schema({
        str: {
            'platform': str,
            'profile': str,
            v.Required('source_ami'): str,
            v.Required('instance_type'): str,
            v.Optional('extra_vars', default={}): dict,
            v.Optional('username', default='ec2-user'): str,
            v.Optional('become', default=True): bool,
            v.Optional('ami_name', default=ami_name): str,
            v.Optional('connection', default='ssh'): v.Or('ssh', 'winrm'),
            v.Optional('connection_timeout', default=600): int,
            v.Optional('port', default=22): int,
            v.Optional('associate_public_ip_address', default=True): bool,
            v.Optional('subnet', default=''): str,
            v.Optional('security_groups', default=[]): [str],
            v.Optional('tags', default={}): {str: str},
            v.Optional('user_data', default=''): v.Or(
                str,
                {'file': str},
            ),
            v.Optional('block_device_mappings', default=[]): [{
                v.Required('device_name'): str,
                'ebs': {
                    'volume_size': int,
                    'volume_type': is_volume_type,
                    'delete_on_termination': bool,
                    'encrypted': bool,
                    'iops': int,
                    'snapshot_id': is_snapshot_id,
                },
                'no_device': str,
                'virtual_name': is_virtual_name,
            }],
        }
    })
