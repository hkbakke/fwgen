import argparse
import signal
from collections import OrderedDict
from pkg_resources import resource_filename
import sys
import subprocess

import yaml
import fwgen


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

def dict_merge(d1, d2):
    """
    Deep merge d1 into d2
    """
    for k, v in d1.items():
        if isinstance(v, dict):
            node = d2.setdefault(k, {})
            dict_merge(v, node)
        else:
            d2[k] = v

    return d2

def setup_yaml():
    """
    Use to preserve dict order from imported yaml config
    """
    represent_dict_order = lambda self, data: self.represent_mapping('tag:yaml.org,2002:map',
                                                                     data.items())
    yaml.add_representer(OrderedDict, represent_dict_order)

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

    user_config = b'/etc/fwgen/config.yml'
    if args.config:
        user_config = args.config

    setup_yaml()
    with open(defaults, 'r') as f:
        config = yaml.load(f)
    with open(user_config, 'r') as f:
        config = dict_merge(yaml.load(f), config)

    fw = fwgen.FwGen(config)
    if args.with_reset:
        fw.reset()
    if args.no_confirm:
        fw.commit()
    else:
        timeout = 30
        if args.timeout:
            timeout = args.timeout

        print('\nRolling back in %d seconds if not confirmed.\n' % timeout)
        fw.apply()
        message = ('The ruleset has been applied successfully! Press \'Enter\' to make the '
                   'new ruleset persistent.\n')

        try:
            wait_for_input(message, timeout)
            fw.save()
        except (TimeoutExpired, KeyboardInterrupt):
            print('No confirmation received. Rolling back...\n')
            fw.rollback()

def main():
    try:
        sys.exit(_main())
    except subprocess.CalledProcessError as e:
        print('ERROR: %s' % e)
        sys.exit(1)
    except fwgen.InvalidChain as e:
        print('ERROR: %s' % e)
        sys.exit(2)
    except KeyboardInterrupt:
        print('ERROR: Aborted by user!')
        sys.exit(130)
