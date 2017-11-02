import argparse
import signal
import sys
import subprocess
from collections import OrderedDict
from pkg_resources import resource_filename

import yaml
import fwgen
from fwgen.helpers import ordered_dict_merge


# Python 2.7 compatibility
try:
    input = raw_input
except NameError:
    pass


class TimeoutExpired(Exception):
    pass

def alarm_handler(signum, frame):
    raise TimeoutExpired

def wait_for_input(message, timeout):
    signal.signal(signal.SIGALRM, alarm_handler)
    signal.alarm(timeout)

    try:
        return input(message)
    finally:
        # Cancel alarm
        signal.alarm(0)

def yaml_load_ordered(stream, Loader=yaml.Loader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)

    return yaml.load(stream, OrderedLoader)

def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', metavar='PATH', help='Override path to config file')
    parser.add_argument('--defaults', metavar='PATH', help='Override path to defaults file')
    parser.add_argument(
        '--with-reset',
        action='store_true',
        help='Clear the firewall before reapplying. Recommended only if ipsets in '
             'use are preventing you from applying the new configuration.'
    )
    parser.add_argument(
        '--no-save',
        action='store_true',
        help='Apply the ruleset but do not make it persistent'
    )
    mutex_group = parser.add_mutually_exclusive_group()
    mutex_group.add_argument('--timeout', metavar='SECONDS', type=int,
                             help='Override timeout for rollback')
    mutex_group.add_argument(
        '--no-confirm',
        action='store_true',
        help="Don't ask for confirmation before storing ruleset"
    )
    args = parser.parse_args()

    defaults = resource_filename(__name__, 'etc/defaults.yml')
    if args.defaults:
        defaults = args.defaults

    user_config = '/etc/fwgen/config.yml'
    if args.config:
        user_config = args.config

    try:
        with open(defaults, 'r') as f:
            config = yaml_load_ordered(f)
        with open(user_config, 'r') as f:
            config = ordered_dict_merge(yaml_load_ordered(f), config)
    except FileNotFoundError as e:
        print('ERROR: %s' % e)
        sys.exit(3)

    fw = fwgen.FwGen(config)

    if args.with_reset:
        fw.reset()

    if args.no_confirm:
        if args.no_save:
            fw.apply()
        else:
            fw.commit()
    else:
        timeout = 30
        if args.timeout:
            timeout = args.timeout

        print('\nRolling back in %d seconds if not confirmed.\n' % timeout)
        fw.apply()

        if args.no_save:
            message = ('The ruleset has been applied successfully! Press \'Enter\' to confirm.\n')
        else:
            message = ('The ruleset has been applied successfully! Press \'Enter\' to make the '
                       'new ruleset persistent.\n')

        try:
            wait_for_input(message, timeout)

            if not args.no_save:
                fw.save()
        except (TimeoutExpired, KeyboardInterrupt):
            print('No confirmation received. Rolling back...\n')
            fw.rollback()

def main():
    try:
        sys.exit(_main())
    except Exception as e:
        print('ERROR: %s' % e)
        sys.exit(1)
    except KeyboardInterrupt:
        print('ERROR: Aborted by user!')
        sys.exit(130)
