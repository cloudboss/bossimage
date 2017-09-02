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
import shutil
import tempfile
import time

from mock import mock

import bossimage.core as bc


tempdir = tempfile.mkdtemp()


def setup():
    bc.create_working_dir = create_working_dir
    bc.instance_files = instance_files
    bc.ec2_connect = probe(ec2_connect)
    bc.wait_for_connection = wait_for_connection
    bc.wait_for_image = probe(wait_for_image)
    bc.run_ansible = probe(run_ansible)
    bc.create_keypair = probe(bc.create_keypair)
    bc.create_instance = probe(bc.create_instance)
    bc.write_playbook = probe(bc.write_playbook)


def teardown():
    shutil.rmtree(tempdir)


def probe(func):
    """
    Decorator to wrap a function with the ability to be probed.
    When the function is called, its name will be added to a list,
    which is stored as an attribute on the probe function.
    """
    def wrapper(*args, **kwargs):
        if func.__name__ in probe.watch:
            probe.called.append(func.__name__)
        return func(*args, **kwargs)
    return wrapper


def reset_probes(watch=[]):
    """
    Clears the list of functions which have been probed. The `watch`
    argument is a list of function names that should be watched for.
    """
    probe.called = []
    probe.watch = watch


def create_working_dir():
    pass


def wait_for_connection(a, b, c, d, e, f):
    time.sleep(1)


def wait_for_image(a):
    time.sleep(1)


def instance_files(instance):
    return dict(
        state='{}/{}-state.yml'.format(tempdir, instance),
        keyfile='{}/{}.pem'.format(tempdir, instance),
        inventory='{}/{}.inventory'.format(tempdir, instance),
        playbook='{}/{}-playbook.yml'.format(tempdir, instance),
    )


@bc.cached
def ec2_connect():
    return mock_ec2()


def run_ansible(a, b, c, d, e):
    pass


def mock_ec2():
    def create_key_pair(KeyName=''):
        keypair = mock.Mock()
        keypair.key_material = 'thiskeyistotallyvalid'
        keypair.key_name = KeyName
        return keypair

    def create_tags(Resources=None, Tags=[]):
        pass

    def create_instances(ImageId='', InstanceType='', MinCount='', MaxCount='',
                         KeyName='', NetworkInterfaces=[],
                         BlockDeviceMappings=[], UserData='',
                         IamInstanceProfile=''):
        instance = mock.Mock()
        instance.id = 'i-00000001'
        instance.private_ip_address = '10.20.30.40'
        instance.public_ip_address = '20.30.40.50'
        instance.load = lambda: None
        instance.reload = lambda: None
        instance.wait_until_running = lambda: time.sleep(1)
        return [instance]

    def images_filter(ImageIds='', Filters=[]):
        image = mock.Mock()
        image.id = 'ami-00000002'
        yield image

    def Instance(id=''):
        def create_image(Name=''):
            image = mock.Mock()
            image.id = 'ami-00000001'
            image.state = 'available'
            image.reload = lambda: None
            return image
        instance = mock.Mock()
        instance.architecture = 'x86_64'
        instance.hypervisor = 'xen'
        instance.virtualization_type = 'hvm'
        instance.create_image = create_image
        instance.load = lambda: None
        instance.password_data = lambda: {'PasswordData': 'uncrackable'}
        return instance

    m = mock.Mock()
    m.create_key_pair = create_key_pair
    m.create_tags = probe(create_tags)
    m.create_instances = probe(create_instances)
    m.images.filter = images_filter
    m.Instance = Instance
    return m
