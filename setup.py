import os

import bossimage

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

def readme():
    try:
        import pypandoc
        return pypandoc.convert(source='README.md', to='rst')
    except:
        with open('README.md') as f:
            return f.read()

version = bossimage.__version__

config = {
    'description': 'Tool to create AMIs with Ansible',
    'long_description': readme(),
    'author': 'Joseph Wright',
    'url': 'https://github.com/cloudboss/bossimage',
    'download_url': 'https://github.com/cloudboss/bossimage/releases/{}'.format(version),
    'author_email': 'rjosephwright@gmail.com',
    'version': version,
    'install_requires': [
        'ansible',
        'boto3',
        'click',
        'pywinrm',
        'voluptuous',
    ],
    'packages': ['bossimage'],
    'package_data': {
        'bossimage': ['*.txt']
    },
    'entry_points': {
        'console_scripts': ['bi = bossimage.cli:main']
    },
    'name': 'bossimage'
}

setup(**config)
