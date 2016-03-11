try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'Tool to create AMIs with Ansible',
    'author': 'Joseph Wright',
    'url': 'https://github.com/cloudboss/bossimage',
    'download_url': 'https://github.com/cloudboss/bossimage/releases',
    'author_email': 'rjosephwright@gmail.com',
    'version': '0.1',
    'install_requires': [
        'ansible',
        'boto3',
        'click',
        'pywinrm',
        'voluptuous',
        'xmltodict',
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
