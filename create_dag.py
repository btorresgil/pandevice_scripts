#!/usr/bin/env python

# Copyright (c) 2016, Palo Alto Networks
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

# Author: Brian Torres-Gil <btorres-gil@paloaltonetworks.com>

"""
create_dag.py
=========

Create a dynamic address group on Panorama

"""

__author__ = 'btorres-gil'

HOSTNAME = ""
APIKEY = ""

import logging
import argparse

from pandevice import panorama
from pandevice import objects


def get_cli_arguments():
    # Get command line arguments
    parser = argparse.ArgumentParser(description="Add dynamic address group to a Palo Alto Networks Panorama")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-d', '--devicegroup', help="Configure in device-group  (omit for 'shared')")
    parser.add_argument('-c', '--commit', action='store_true', help="Perform Panorama commit after configuration change")
    parser.add_argument('-a', '--commitall', action='store_true', help="Commit change to firewalls (implies -c)")
    # Palo Alto Networks related arguments
    dag_group = parser.add_argument_group('Dynamic Address Group')
    dag_group.add_argument('name', help="Name of Dynamic Address Group")
    dag_group.add_argument('match', help="Match string (eg. \"'tag1' and 'tag2'\")")
    dag_group.add_argument('description', help="Description of the dynamic address group")
    return parser.parse_args()


def setup_logging(args):
    ### Set up logger
    # Logging Levels
    # WARNING is 30
    # INFO is 20
    # DEBUG is 10
    if args.verbose is None:
        return
    logging_level = 20 - (args.verbose * 10)
    if logging_level <= logging.DEBUG:
        logging_format = '%(levelname)s:%(name)s:%(message)s'
    else:
        logging_format = '%(message)s'
    logging.basicConfig(format=logging_format, level=logging_level)


def main():

    args = get_cli_arguments()
    setup_logging(args)

    # The Panorama object. This is the root object of the config tree.
    pano = panorama.Panorama(hostname=HOSTNAME,
                             api_key=APIKEY,
                             )

    # Add the devicegroup as a child of the Panorama
    if args.devicegroup is not None:
        scope = pano.add(panorama.DeviceGroup(args.devicegroup))
    else:
        scope = pano

    # Create a dynamic address group in the required scope
    addressgroup = scope.add(objects.AddressGroup(name=args.name,
                                                  dynamic_value=args.tags,
                                                  description=args.description,
                                                  ))
    # Push the new dynamic address group to the live Panorama device
    addressgroup.create()

    # Perform a commit if requested
    if args.commit or args.commitall:
        pano.commit()
    if args.commitall and args.devicegroup is not None:
        pano.commit_all(devicegroup=args.devicegroup)
    elif args.commitall:
        pano.commit_all()


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()