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
commit.py
=========

Initiate a commit on a Palo Alto Networks Panorama

"""

__author__ = 'btorres-gil'

import logging
import argparse

from pandevice import panorama

from credentials import *


def get_cli_arguments():
    # Get command line arguments
    parser = argparse.ArgumentParser(description="Initiate commit on a Palo Alto Networks Panorama")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-d', '--devicegroup', help="Commit device-group")
    parser.add_argument('-a', '--commitall', action='store_true', help="Commit change to firewalls")
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

    # Perform a commit if requested
    pano.commit(sync=True)
    if args.commitall:
        pano.commit_all(sync=True, sync_all=True, devicegroup=args.devicegroup)


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()