# Copyright 2018 Joseph Wright <joseph@cloudboss.co>
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
import contextlib
import json
import sys

import boto3 as boto
import click

import bossimage as b
import bossimage.core as bc


def ec2_connect():
    return boto.Session().resource('ec2')


@click.group()
def main(): pass


@main.command('list')
def lst():
    with load_config() as c:
        statuses = bc.statuses(c)
    longest = sorted(len(status[0]) for status in statuses)[-1]
    for instance, created in statuses:
        status = 'Created' if created else 'Not created'
        click.echo('{:{width}}{}'.format(instance, status, width=longest+4))


@main.command()
@click.option('-p', '--phase', type=click.Choice(['build', 'test']),
              default='build')
@click.argument('instance')
def login(phase, instance):
    with load_config() as c:
        validate_instance(instance, c)
        if c[instance][phase]['connection'] == 'winrm':
            click.echo('Login unsupported for winrm connections', err=True)
        bc.login(instance, c[instance][phase], phase)


@main.command()
@click.option('-a', '--attribute')
@click.argument('instance')
def info(attribute, instance):
    with load_config() as c:
        validate_instance(instance, c)
    if not attribute:
        click.echo(json.dumps(c[instance], indent=2, separators=(',', ': ')))
    else:
        try:
            click.echo(find_nested_attr(c[instance], attribute))
        except KeyError:
            click.echo('No such attribute {}'.format(attribute), err=True)
            raise click.Abort()


@main.command()
def version():
    click.echo(b.__version__)


@main.group()
def make(): pass


@make.command('build')
@click.argument('instance')
@click.option('-v', '--verbosity', count=True,
              help='Verbosity, may be repeated up to 4 times')
def make_build(instance, verbosity):
    with load_config() as c:
        validate_instance(instance, c)
        ec2 = ec2_connect()
        sys.exit(bc.make_build(ec2, instance, c[instance]['build'], verbosity))


@make.command('image')
@click.argument('instance')
@click.option('-w', '--wait/--no-wait', default=True,
              help='Wait for image to be available')
def make_image(instance, wait):
    with load_config() as c:
        validate_instance(instance, c)
        ec2 = ec2_connect()
        try:
            bc.make_image(ec2, instance, c[instance]['image'], wait)
        except bc.StateError as e:
            click.echo(e, err=True)
            raise click.Abort()


@make.command('test')
@click.argument('instance')
@click.option('-v', '--verbosity', count=True,
              help='Verbosity, may be repeated up to 4 times')
def make_test(instance, verbosity):
    with load_config() as c:
        validate_instance(instance, c)
        ec2 = ec2_connect()
        try:
            sys.exit(bc.make_test(
                ec2, instance, c[instance]['test'], verbosity)
            )
        except bc.StateError as e:
            click.echo(e, err=True)
            raise click.Abort()


@main.group()
def clean(): pass


@clean.command('build')
@click.argument('instance')
def clean_build(instance):
    bc.clean_build(ec2_connect(), instance)


@clean.command('test')
@click.argument('instance')
def clean_test(instance):
    bc.clean_test(ec2_connect(), instance)


@clean.command('image')
@click.argument('instance')
def clean_image(instance):
    bc.clean_image(ec2_connect(), instance)


def validate_instance(instance, config):
    if instance not in config:
        click.echo('No such instance {} configured'.format(instance), err=True)
        raise click.Abort()


def find_nested_attr(config, attr):
    """
    Takes a config dictionary and an attribute string as input and tries to
    find the attribute in the dictionary. The attribute may use dots to
    indicate levels of depth within the dictionary.

    Example:
    find_nested_attr({'one': {'two': {'three': 3}}}, 'one.two.three')
    --> 3
    """
    obj = config.copy()
    for section in attr.split('.'):
        obj = obj[section]
    return obj


@contextlib.contextmanager
def load_config():
    try:
        c = bc.load_config()
        yield c
    except bc.ConfigurationError as e:
        click.echo(e, err=True)
        raise click.Abort()
