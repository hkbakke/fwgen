import argparse
import signal
import sys
import json
import logging
from collections import OrderedDict
from pkg_resources import resource_filename
from subprocess import CalledProcessError

import yaml
import fwgen
from fwgen.helpers import ordered_dict_merge


LOGGER = logging.getLogger(__name__)

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
    parser.add_argument('--config-json', metavar='JSON', help='JSON formatted config')
    parser.add_argument('--with-reset', action='store_true',
                        help='Clear the firewall before reapplying. Recommended only if ipsets '
                             'in use are preventing you from applying the new configuration.')
    parser.add_argument('--no-save', action='store_true',
                        help='Apply the ruleset but do not make it persistent')
    parser.add_argument('--flush-connections', action='store_true',
                        help='Flush all connections after applying ruleset')
    parser.add_argument(
        '--log-level',
        choices=[
            'critical',
            'error',
            'warning',
            'info',
            'debug'
        ],
        default='info',
        help='Set log level for console output'
    )

    mutex_group = parser.add_mutually_exclusive_group()
    mutex_group.add_argument('--timeout', metavar='SECONDS', type=int,
                             help='Override timeout for rollback')
    mutex_group.add_argument('--no-confirm', action='store_true',
                             help="Don't ask for confirmation before storing ruleset")

    args = parser.parse_args()

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(args.log_level.upper())
    console = logging.StreamHandler()
    logger.addHandler(console)

    #
    # Configuration merge order. Each merge overrides the previous one if a parameter
    # is provided in both configurations.
    #
    #   1. config from defaults file
    #   2. config from config file
    #   3. config provided at runtime via --config-json
    #
    defaults = resource_filename(__name__, 'etc/defaults.yml')
    if args.defaults:
        defaults = args.defaults
        logger.debug('Using defaults file %s', defaults)

    user_config = '/etc/fwgen/config.yml'
    if args.config:
        user_config = args.config
        logger.debug('Using config file %s', user_config)

    try:
        with open(defaults, 'r') as f:
            config = yaml_load_ordered(f)
        with open(user_config, 'r') as f:
            config = ordered_dict_merge(yaml_load_ordered(f), config)
    except FileNotFoundError as e:
        logger.error(str(e))
        sys.exit(3)

    if args.config_json:
        json_config = json.loads(args.config_json, object_pairs_hook=OrderedDict)
        config = ordered_dict_merge(json_config, config)

    logger.debug('Resulting config: %s', json.dumps(config, indent=2))

    #
    # Start doing actual firewall stuff
    #
    fw = fwgen.FwGen(config)

    try:
        if args.with_reset:
            fw.reset()

        if args.no_confirm:
            if args.no_save:
                fw.apply(args.flush_connections)
            else:
                fw.apply(args.flush_connections)
                fw.save()
        else:
            timeout = 30
            if args.timeout:
                timeout = args.timeout

            logger.info('\nRolling back in %d seconds if not confirmed' % timeout)
            fw.apply(args.flush_connections)

            if args.no_save:
                message = ('\nThe ruleset has been applied successfully! Press \'Enter\' to confirm.')
            else:
                message = ('\nThe ruleset has been applied successfully! Press \'Enter\' to make the '
                           'new ruleset persistent.')

            try:
                wait_for_input(message, timeout)

                if not args.no_save:
                    fw.save()
            except (TimeoutExpired, KeyboardInterrupt):
                logger.info('\nNo confirmation received. Rolling back...')
                fw.rollback()
    except CalledProcessError as e:
        logger.error(str(e))
        return 1
    except fwgen.RulesetError as e:
        logger.error(str(e))
        return 1
    except fwgen.InvalidChain as e:
        logger.error(str(e))
        return 1

def main():
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        print('Aborted by user!')
        sys.exit(130)
