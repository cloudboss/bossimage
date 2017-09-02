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
from setuptools import setup


def readme():
    try:
        import pypandoc
        return pypandoc.convert(source='README.md', to='rst')
    except:
        with open('README.md') as f:
            return f.read()


config = {
    'description': 'Tool to create AMIs with Ansible',
    'long_description': readme(),
    'author': 'Joseph Wright',
    'url': 'https://github.com/cloudboss/bossimage',
    'download_url': 'https://pypi.python.org/pypi/friend',
    'author_email': 'joseph@cloudboss.co',
    'setup_requires': [
        'setuptools_scm',
    ],
    'use_scm_version': True,
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
    'name': 'bossimage',
    'test_suite': 'nose.collector',
}

setup(**config)
