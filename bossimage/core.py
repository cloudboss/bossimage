# Copyright 2016 Joseph Wright <rjosephwright@gmail.com>
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
import functools as f
import itertools
import json
import os
import random
import re
import shutil
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
import pkg_resources as pr
import voluptuous as v

class ConnectionTimeout(Exception): pass

class Spinner(t.Thread):
    def __init__(self, waitable):
        t.Thread.__init__(self)
        self.msg = 'Waiting for {} to be available ...  '.format(waitable)
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

    @f.wraps(func)
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
        return { snake_to_camel(k): camelify(v) for k, v in spec.items() }
    else:
        return spec

def gen_keyname():
    letters = string.ascii_letters + string.digits
    base = 'bossimage-'
    rand = ''.join([letters[random.randrange(0, len(letters))] for _ in range(10)])
    return base + rand

def create_working_dir():
    if not os.path.exists('.boss'): os.mkdir('.boss')

def user_data(config):
    if type(config['user_data']) == dict:
        with open(config['user_data']['file']) as f:
            return f.read()

    if not config['user_data'] and config['connection'] == 'winrm':
        ud = pr.resource_string('bossimage', 'win-userdata.txt')
    else:
        ud = config['user_data']
    return ud

def create_instance(config, files, keyname):
    ec2 = ec2_connect()
    kp = ec2.create_key_pair(KeyName=keyname)

    with open(files['keyfile'], 'w') as f:
        f.write(kp.key_material)
    os.chmod(files['keyfile'], 0600)

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

    (instance,) = ec2.create_instances(**instance_params)
    print('Created instance {}'.format(instance.id))

    if config['tags']:
        tags = [{'Key': k, 'Value': v} for k, v in config['tags'].items()]
        ec2.create_tags(Resources=[instance.id], Tags=tags)

    with Spinner('instance'):
        instance.wait_until_running()

    instance.reload()
    return instance

def role_name():
    return os.path.basename(os.getcwd())

def role_version():
    if os.path.exists('.role-version'):
        with open('.role-version') as f:
            version = f.read().strip()
    else:
        version = 'unset'
    return version

def decrypt_password(password_file, keyfile):
    openssl = subprocess.Popen([
        'openssl', 'rsautl', '-decrypt',
        '-in', password_file,
        '-inkey', keyfile,
    ], stdout=subprocess.PIPE)
    password, _ = openssl.communicate()
    return password

def write_files(files, ec2_instance, keyname, config, password):
    if config['associate_public_ip_address']:
        ip_address = ec2_instance.public_ip_address
    else:
        ip_address = ec2_instance.private_ip_address

    with open(files['config'], 'w') as f:
        f.write(yaml.safe_dump(dict(
            id=ec2_instance.id,
            ip=ip_address,
            keyname=keyname,
            platform=config['platform'],
        )))

    with open(files['inventory'], 'w') as f:
        inventory = '{} ' \
                    'ansible_ssh_private_key_file={} ' \
                    'ansible_user={} ' \
                    'ansible_password={} ' \
                    'ansible_port={} ' \
                    'ansible_connection={}'.format(
                        ip_address,
                        files['keyfile'],
                        config['username'],
                        password,
                        config['port'],
                        config['connection'],
                    )
        f.write(inventory)
    os.chmod(files['inventory'], 0600)

    with open(files['playbook'], 'w') as f:
        f.write(yaml.safe_dump([dict(
            hosts='all',
            become=config['become'],
            roles=[role_name()],
        )]))

def load_or_create_instance(config):
    instance = '{}-{}'.format(config['platform'], config['profile'])
    files = instance_files(instance)

    if not os.path.exists(files['config']):
        keyname = gen_keyname()
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

        write_files(files, ec2_instance, keyname, config, password)

    with open(files['config']) as f:
        return yaml.load(f)

def wait_for_image(image):
    with Spinner('image'):
        while(True):
            image.reload()
            if image.state == 'available':
                break
            else:
                time.sleep(15)

def wait_for_password(ec2_instance):
    with Spinner('password'):
        while True:
            ec2_instance.reload()
            pd = ec2_instance.password_data()
            if pd['PasswordData']:
                return pd['PasswordData']
            else:
                time.sleep(15)

def wait_for_connection(addr, port, inventory, connection, end):
    ping = 'win_ping' if connection == 'winrm' else 'ping'
    env = os.environ.copy()
    env.update(dict(ANSIBLE_HOST_KEY_CHECKING='False'))

    while(True):
        if time.time() > end:
            raise ConnectionTimeout('Timeout while connecting to {}:{}'.format(addr, port))
        try:
            # First check if port is open.
            socket.create_connection((addr, port), 1)

            # We didn't raise an exception, so port is open.
            # Now check if we can actually log in.
            with open('/dev/null', 'wb') as devnull:
                ret = subprocess.call([
                    'ansible', 'all', '-i', inventory, '-m', ping
                ], stderr=devnull, stdout=devnull, env=env)
                if ret == 0: break
                else: raise
        except:
            time.sleep(15)

def run(instance, config, verbosity):
    create_working_dir()
    files = instance_files(instance)

    instance_info = load_or_create_instance(config)

    ip = instance_info['ip']
    port = config['port']
    end = time.time() + config['connection_timeout']
    with Spinner('connection to {}:{}'.format(ip, port)):
        wait_for_connection(ip, port, files['inventory'], config['connection'], end)

    env = os.environ.copy()

    env.update(dict(ANSIBLE_ROLES_PATH='.boss/roles:..'))

    ansible_galaxy_args = ['ansible-galaxy', 'install', '-r', 'requirements.yml']
    if verbosity:
        ansible_galaxy_args.append('-' + 'v' * verbosity)
    ansible_galaxy = subprocess.Popen(ansible_galaxy_args, env=env)
    ansible_galaxy.wait()

    env.update(dict(ANSIBLE_HOST_KEY_CHECKING='False'))

    ansible_playbook_args = ['ansible-playbook', '-i', files['inventory']]
    if verbosity:
        ansible_playbook_args.append('-' + 'v' * verbosity)
    if config['extra_vars']:
        ansible_playbook_args += ['--extra-vars', json.dumps(config['extra_vars'])]
    ansible_playbook_args.append(files['playbook'])
    ansible_playbook = subprocess.Popen(ansible_playbook_args, env=env)
    ansible_playbook.wait()

def image(instance, config):
    files = instance_files(instance)
    with open(files['config']) as f:
        c = yaml.load(f)

    ec2 = ec2_connect()
    ec2_instance = ec2.Instance(id=c['id'])
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

    wait_for_image(image)

def delete(instance):
    files = instance_files(instance)

    with open(files['config']) as f:
        c = yaml.load(f)

    ec2 = ec2_connect()

    ec2_instance = ec2.Instance(id=c['id'])
    ec2_instance.terminate()

    kp = ec2.KeyPair(name=c['keyname'])
    kp.delete()

    for f in files.values():
        try:
            os.unlink(f)
        except OSError:
            print('Error removing {}, skipping'.format(f))

def statuses(config):
    def exists(instance):
        return os.path.exists('.boss/{}.yml'.format(instance))
    return [(instance, exists(instance)) for instance in config.keys()]

def login(instance, config):
    files = instance_files(instance)

    with open(files['config']) as f:
        c = yaml.load(f)

    ssh = subprocess.Popen([
        'ssh', '-i', files['keyfile'],
        '-l', config['username'], c['ip']
    ])
    ssh.wait()

def instance_files(instance):
    return dict(
        config='.boss/{}.yml'.format(instance),
        keyfile='.boss/{}.pem'.format(instance),
        inventory='.boss/{}.inventory'.format(instance),
        playbook='.boss/{}-playbook.yml'.format(instance),
    )

def resource_id_for(service, name, prefix, flt):
    if name.startswith(prefix): return name
    item = list(service.filter(Filters=[flt]))
    if item: return item[0].id

def ami_id_for(name):
    ec2 = ec2_connect()
    return resource_id_for(
        ec2.images, name, 'ami-',
        { 'Name': 'name', 'Values': [name] }
    )

def sg_id_for(name):
    ec2 = ec2_connect()
    return resource_id_for(
        ec2.security_groups, name, 'sg-',
        { 'Name': 'group-name', 'Values': [name] }
    )

def subnet_id_for(name):
    ec2 = ec2_connect()
    return resource_id_for(
        ec2.subnets, name, 'subnet-',
        { 'Name': 'tag:Name', 'Values': [name] }
    )

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
                k: v for k, v in c['driver'].items() if k not in platform
            })
            merged[instance].update({
                k: v for k, v in profile.items() if k != 'name'
            })
            merged[instance]['profile'] = profile['name']
    return merged

def invalid(kind, item):
    return v.Invalid('Invalid {}: {}'.format(kind, item))

def re_validator(pat, s, kind):
    if not re.match(pat, s): raise invalid(kind, s)
    return s

def coll_validator(coll, kind, thing):
    if thing not in coll: raise invalid(kind, thing)
    return thing

def is_subnet_id(s):
    return re_validator(r'subnet-[0-9a-f]{8}', s, 'subnet_id')

def is_snapshot_id(s):
    return re_validator(r'snap-[0-9a-f]{8}', s, 'snapshot_id')

def is_virtual_name(s):
    return re_validator(r'ephemeral\d+', s, 'virtual_name')

def is_volume_type(s):
    return coll_validator(('gp2', 'io1', 'standard'), 'volume_type', s)

def pre_merge_schema():
    default_profiles = [{
        'name': 'default',
        'extra_vars': {}
    }]
    return v.Schema({
        v.Optional('driver', default={}): { v.Extra: object },
        v.Required('platforms'): [{
            v.Required('name'): str,
        }],
        v.Optional('profiles', default=default_profiles): [{
            v.Required('name'): str,
        }],
    }, extra=v.ALLOW_EXTRA)

def post_merge_schema():
    default_ami_name = '%(role)s.%(profile)s.%(platform)s.%(vtype)s.%(arch)s.%(version)s'
    return v.Schema({
        str: {
            'platform': str,
            'profile': str,
            v.Required('source_ami'): str,
            v.Required('instance_type'): str,
            v.Optional('extra_vars', default={}): dict,
            v.Optional('username', default='ec2-user'): str,
            v.Optional('become', default=True): bool,
            v.Optional('ami_name', default=default_ami_name): str,
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
