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
import contextlib
import os
import sys

import click
import voluptuous as v
import yaml

import bossimage as b
import bossimage.core as bc

@click.group()
def main(): pass

@main.command()
@click.argument('instance')
@click.option('-v', '--verbosity', count=True,
              help='Verbosity, may be repeated up to 4 times')
def run(instance, verbosity):
    with load_config() as c:
        validate_instance(instance, c)
        sys.exit(bc.run(instance, c[instance], verbosity))

@main.command()
@click.argument('instance')
def image(instance):
    with load_config() as c:
        validate_instance(instance, c)
        bc.image(instance, c[instance])

@main.command()
@click.argument('instance')
def delete(instance):
    bc.delete(instance)

@main.command('list')
def lst():
    with load_config() as c:
        statuses = bc.statuses(c)
    longest = sorted(len(status[0]) for status in statuses)[-1]
    for instance, created in statuses:
        status = 'Created' if created else 'Not created'
        click.echo('{:{width}}{}'.format(instance, status, width=longest+4))

@main.command()
@click.argument('instance')
def login(instance):
    with load_config() as c:
        validate_instance(instance, c)
        if c[instance]['connection'] == 'winrm':
            click.echo('Login unsupported for winrm connections')
            raise click.Abort()
        bc.login(instance, c[instance])

def validate_instance(instance, config):
    if instance not in config:
        click.echo('No such instance {} configured'.format(instance))
        raise click.Abort()

@main.command()
def version():
    click.echo(b.__version__)

@contextlib.contextmanager
def load_config():
    try:
        c = bc.load_config()
        yield c
    except bc.ConfigurationError as e:
        click.echo(e)
        raise click.Abort()
