import shutil
import tempfile

import bossimage.core as bc


tempdir = tempfile.mkdtemp()


def setup():
    bc.create_working_dir = create_working_dir
    bc.instance_files = instance_files


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
