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
create_rule.py
==============

Create a security rule on Panorama

"""

__author__ = 'btorres-gil'

import logging
import argparse

from pandevice import panorama
from pandevice import policies

from credentials import *


def get_cli_arguments():
    # Get command line arguments
    parser = argparse.ArgumentParser(description="Add security rule to a Palo Alto Networks Panorama")
    parser.add_argument('-v', '--verbose', action='count', help="Verbose (-vv for extra verbose)")
    parser.add_argument('-d', '--devicegroup', help="Configure in device-group  (omit for 'shared')")
    parser.add_argument('-a', '--above', help="Name of a rule to put this rule above")
    # Palo Alto Networks related arguments
    rule_group = parser.add_argument_group('Dynamic Address Group')
    rule_group.add_argument('-n', '--name', required=True, help="Name of Rule")
    #rule_group.add_argument('-t', '--tags', help="Administrative tags")
    rule_group.add_argument('--szone', help="Source Zone")
    rule_group.add_argument('--saddr', help="Source Addresses")
    rule_group.add_argument('--dzone', help="Destination Zone")
    rule_group.add_argument('--daddr', help="Destination Addresses")
    rule_group.add_argument('--application', help="Application ID")
    rule_group.add_argument('--action', default="allow", help="Action (allow, deny) Default: allow")
    rule_group.add_argument('--log', help="Log Forwarding Profile Name")
    rule_group.add_argument('--group', help="Profile Group Name")
    rule_group.add_argument('--virus', help="Antivirus Profile Name")
    rule_group.add_argument('--spyware', help="Anti-Spyware Profile Name")
    rule_group.add_argument('--threat', help="Threat Prevention Profile Name")
    rule_group.add_argument('--url', help="URL-Filtering Profile Name")
    rule_group.add_argument('--file', help="File Blocking Profile Name")
    rule_group.add_argument('--wildfire', help="Wildfire Profile Name")
    rule_group.add_argument('--data', help="Data Filtering Profile Name")
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

    # Create a security rule in the required scope
    rulebase = scope.add(policies.PreRulebase())
    rule = rulebase.add(policies.SecurityRule(args.name, args.szone, args.dzone,
                                              source=args.saddr,
                                              destination=args.daddr,
                                              application=args.application,
                                              action=args.action,
                                              log_setting=args.log,
                                              group=args.group,
                                              virus=args.virus,
                                              spyware=args.spyware,
                                              vulnerability=args.threat,
                                              url_filtering=args.url,
                                              file_blocking=args.file,
                                              wildfire_analysis=args.wildfire,
                                              data_filtering=args.data,
                                              #tags=args.tags,
                                              description=args.description,
                                              ))
    # Push the new security rule to the live Panorama device
    rule.create()

    if args.above is not None:
        pano.xapi.move(rule.xpath(), "above", args.above)


# Call the main() function to begin the program if not
# loaded as a module.
if __name__ == '__main__':
    main()