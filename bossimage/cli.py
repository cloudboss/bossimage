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
import bossimage.core as bc

@click.group()
def main(): pass

@main.command()
@click.argument('platform')
def run(platform):
    config = bc.load_config()
    if not config: return 1

    bc.create_working_dir()
    instance_info = bc.load_instance_info(config, platform)

    bc.wait_for_ssh(instance_info['ip'])

    bc.run(platform)

@main.command()
@click.argument('platform')
def image(platform):
    config = bc.load_config()
    if not config: return 1

    bc.image(platform)

@main.command()
@click.argument('platform')
def delete(platform):
    config = bc.load_config()
    if not config: return 1

    bc.delete(platform)
