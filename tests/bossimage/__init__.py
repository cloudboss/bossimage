import shutil
import tempfile

from mock import mock

import bossimage.core as bc


tempdir = tempfile.mkdtemp()


def setup():
    bc.create_working_dir = create_working_dir
    bc.instance_files = instance_files
    bc.ec2_connect = ec2_connect


def teardown():
    shutil.rmtree(tempdir)


def create_working_dir():
    pass


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


def mock_ec2():
    def create_key_pair(KeyName=''):
        keypair = mock.Mock()
        keypair.key_material = 'thiskeyistotallyvalid'
        keypair.key_name = KeyName
        return keypair

    def create_tags(Resources=None, Tags=[]):
        pass

    def create_instances(ImageId='', InstanceType='', MinCount='', MaxCount='',
        KeyName='', NetworkInterfaces=[], BlockDeviceMappings=[], UserData=''):
        instance = mock.Mock()
        instance.id = 'i-00000001'
        instance.private_ip_address = '10.20.30.40'
        instance.public_ip_address = '20.30.40.50'
        instance.load = lambda: None
        instance.reload = lambda: None
        instance.wait_until_running = lambda: None
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
    m.create_tags = create_tags
    m.create_instances = create_instances
    m.images.filter = images_filter
    m.Instance = Instance
    return m
