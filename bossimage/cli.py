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

import bossimage.core as bc

@click.group()
def main(): pass

@main.command()
@click.argument('instance')
@click.option('-v', '--verbosity', count=True,
              help='Verbosity, may be repeated up to 4 times')
def run(instance, verbosity):
    config = load_config()[instance]

    bc.create_working_dir()

    instance_info = bc.load_or_create_instance(config)

    bc.wait_for_ssh(instance_info['ip'])

    bc.run(instance, config['extra_vars'], verbosity)

@main.command()
@click.argument('instance')
def image(instance):
    bc.image(instance)

@main.command()
@click.argument('instance')
def delete(instance):
    bc.delete(instance)

@main.command('list')
def lst():
    platforms = list_of('platforms')
    profiles = list_of('profiles')
    instances = ['{}-{}'.format(pl, pr) for pl in platforms for pr in profiles]
    for i in instances: click.echo(i)

def list_of(key):
    config = load_config()
    return [k['name'] for k in config[key]]

@bc.cached
def load_config():
    pre_validate = bc.pre_merge_schema()
    post_validate = bc.post_merge_schema()
    try:
        with open('.boss.yml') as f:
            c = pre_validate(yaml.load(f))
        return post_validate(bc.merge_config(c))
    except IOError as e:
        click.echo('Error loading .boss.yml: {}'.format(e.strerror))
        raise click.Abort()
    except v.Invalid as e:
        click.echo('Error validating .boss.yml: {}'.format(e))
        raise click.Abort()
