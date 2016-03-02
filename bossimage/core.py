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
import boto3 as boto
import functools as f
import os
import random
import shutil
import socket
import string
import subprocess
import time
import tempfile
import yaml

def cached(func):
    cache = {}

    @f.wraps(func)
    def wrapper(*args, **kwargs):
        key = func.__name__ + str(sorted(args)) + str(sorted(kwargs.items()))
        if key not in cache:
            print("Adding '{}' to cache".format(key))
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

def keyname():
    letters = string.ascii_letters + string.digits
    base = 'bossimage-'
    rand = ''.join([letters[random.randrange(0, len(letters))] for _ in range(10)])
    return base + rand

def create_working_dir():
    if not os.path.exists('.boss'): os.mkdir('.boss')

def load_config():
    if os.path.exists('.boss.yml'):
        with open('.boss.yml') as f:
            c = yaml.load(f)
        return c

def load_platform_info(config, platform):
    pi = [p for p in config['platforms'] if p['name'] == platform]
    if pi: return pi[0]

def create_instance(platform_info):
    ec2 = ec2_connect()
    kn = keyname()
    kp = ec2.create_key_pair(KeyName=kn)
    platform = platform_info['name']

    pf = platform_files(platform)

    with open(pf['keyfile'], 'w') as f:
        f.write(kp.key_material)
    os.chmod(pf['keyfile'], 0600)

    (instance,) = ec2.create_instances(
        ImageId=platform_info['driver']['image'],
        InstanceType=platform_info['driver']['instance_type'],
        MinCount=1,
        MaxCount=1,
        KeyName=kn,
        NetworkInterfaces=[dict(
            DeviceIndex=0,
            AssociatePublicIpAddress=True,
        )],
        BlockDeviceMappings=camelify(
            platform_info['driver'].get('block_device_mappings', [])
        ),
    )
    print('Created instance {}'.format(instance.id))

    instance.wait_until_running()
    print('Instance is running')

    instance.load()

    with open(pf['config'], 'w') as f:
        f.write(yaml.safe_dump(dict(
            id=instance.id,
            ip=instance.public_ip_address,
            keyname=kn,
        )))

    with open(pf['inventory'], 'w') as f:
        inventory = '{} ansible_ssh_private_key_file={} ansible_user={}'.format(
            instance.public_ip_address,
            pf['keyfile'],
            platform_info.get('username', 'ec2-user'),
        )
        f.write(inventory)

    with open(pf['playbook'], 'w') as f:
        f.write(yaml.safe_dump([dict(
            hosts='all',
            become=True,
            roles=[os.path.basename(os.getcwd())],
        )]))

def load_instance_info(config, platform):
    platform_info = load_platform_info(config, platform)
    if not platform_info: return

    pf = platform_files(platform)

    if not os.path.exists(pf['config']):
        create_instance(platform_info)

    with open(pf['config']) as f:
        return yaml.load(f)

def wait_for_image(image):
    while(True):
        image.reload()
        if image.state == 'available':
            break
        else:
            time.sleep(5)

def wait_for_ssh(addr):
    while(True):
        try:
            print('Attempting ssh connection to {} ... '.format(addr), end='')
            socket.create_connection((addr, 22), 1)
            print('ok')
            break
        except:
            print('failed, will retry')
            time.sleep(5)

def run(platform):
    pf = platform_files(platform)

    env = os.environ.copy()

    env.update(dict(ANSIBLE_ROLES_PATH='.boss/roles:..'))

    ansible_galaxy = subprocess.Popen(
        ['ansible-galaxy', 'install', '-r', 'requirements.yml'],
        env=env
    )
    ansible_galaxy.wait()

    env.update(dict(ANSIBLE_HOST_KEY_CHECKING='False'))

    ansible_playbook = subprocess.Popen(
        ['ansible-playbook', '-i', pf['inventory'], '-vvvv', pf['playbook']],
        env=env
    )
    ansible_playbook.wait()

def image(platform):
    pf = platform_files(platform)
    with open(pf['config']) as f:
        c = yaml.load(f)

    ec2 = ec2_connect()

    instance = ec2.Instance(id=c['id'])
    image = instance.create_image(Name=platform)
    print('Created image {}'.format(image.id))

    wait_for_image(image)
    print('Image is available')

def delete(platform):
    pf = platform_files(platform)

    with open(pf['config']) as f:
        c = yaml.load(f)

    ec2 = ec2_connect()

    instance = ec2.Instance(id=c['id'])
    instance.terminate()

    kp = ec2.KeyPair(name=c['keyname'])
    kp.delete()

    for f in pf.values(): os.unlink(f)

def platform_files(platform):
    return dict(
        config='.boss/{}.yml'.format(platform),
        keyfile='.boss/{}.pem'.format(platform),
        inventory='.boss/{}.inventory'.format(platform),
        playbook='.boss/{}-playbook.yml'.format(platform),
    )
