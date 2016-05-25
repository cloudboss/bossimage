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
import click
import os
import yaml

import voluptuous as v

import bossimage as b
import bossimage.core as bc

@click.group()
def main(): pass

@main.command()
@click.argument('instance')
@click.option('-v', '--verbosity', count=True,
              help='Verbosity, may be repeated up to 4 times')
def run(instance, verbosity):
    config = load_config()[instance]
    bc.run(instance, config, verbosity)

@main.command()
@click.argument('instance')
def image(instance):
    config = load_config()[instance]
    bc.image(instance, config)

@main.command()
@click.argument('instance')
def delete(instance):
    bc.delete(instance)

@main.command('list')
def lst():
    statuses = bc.statuses(load_config())
    longest = sorted(len(status[0]) for status in statuses)[-1]
    for instance, created in statuses:
        status = 'Created' if created else 'Not created'
        click.echo('{:{width}}{}'.format(instance, status, width=longest+4))

@main.command()
@click.argument('instance')
def login(instance):
    config = load_config()[instance]
    if config['connection'] == 'winrm':
        click.echo('Login unsupported for winrm connections')
        raise click.Abort()
    bc.login(instance, config)

@main.command()
def version():
    click.echo(b.__version__)

@bc.cached
def load_config(path='.boss.yml'):
    pre_validate = bc.pre_merge_schema()
    post_validate = bc.post_merge_schema()
    try:
        with open(path) as f:
            c = pre_validate(yaml.load(f))
        return post_validate(bc.merge_config(c))
    except IOError as e:
        click.echo('Error loading {}: {}'.format(path, e.strerror))
        raise click.Abort()
    except v.Invalid as e:
        click.echo('Error validating {}: {}'.format(path, e))
        raise click.Abort()
