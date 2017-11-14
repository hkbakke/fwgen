import argparse
import signal
import sys
import json
import logging
import traceback
from collections import OrderedDict
from pathlib import Path

from fwgen import fwgen
from fwgen.helpers import yaml_load_ordered, ordered_dict_merge, get_etc


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

def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--create-config-dir', metavar='PATH', default=False, nargs='?',
                        const=Path(get_etc()) / 'fwgen', help='Create initial config dir')
    parser.add_argument('--config', metavar='PATH', default='/etc/fwgen/config.yml',
                        help='Override path to config file')
    parser.add_argument('--defaults', metavar='PATH',
                        default=str(Path(fwgen.__file__).parent / 'etc/defaults.yml'),
                        help='Override path to defaults file')
    parser.add_argument('--config-json', metavar='JSON', help='JSON formatted config')
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
    mutex_1 = parser.add_mutually_exclusive_group()
    mutex_1.add_argument('--timeout', metavar='SECONDS', type=int, default=20,
                         help='Override timeout for rollback')
    mutex_1.add_argument('--no-confirm', action='store_true',
                         help="Don't ask for confirmation before storing ruleset")
    mutex_2 = parser.add_mutually_exclusive_group()
    mutex_2.add_argument('--clear', action='store_true', help='Clear the ruleset')
    mutex_2.add_argument('--restore', action='store_true', help='Restore saved ruleset')
    args = parser.parse_args()

    # Set up logging
    logger = logging.getLogger()
    logger.setLevel(args.log_level.upper())
    fmt = logging.Formatter('%(asctime)s [%(levelname)s] %(message)s')
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    logger.addHandler(console)

    try:
        if args.create_config_dir is not False:
            configdir = fwgen.ConfigDir(Path(args.create_config_dir))
            configdir.create()
            return 0

        #
        # Configuration merge order. Each merge overrides the previous one if a parameter
        # is provided in both configurations.
        #
        #   1. config from defaults file
        #   2. config from config file
        #   3. config provided at runtime via --config-json
        #
        logger.debug("Loading defaults file '%s'", args.defaults)
        with open(args.defaults, 'r') as f:
            config = yaml_load_ordered(f) or {}

        logger.debug("Loading config file '%s'", args.config)
        try:
            with open(args.config, 'r') as f:
                user_config = yaml_load_ordered(f) or {}
            config = ordered_dict_merge(user_config, config)
        except FileNotFoundError as e:
            if not args.config_json:
                raise
            logger.warning("Config file '%s' not found. All non-default settings must "
                           "be fed via '--config-json'", args.config)

        if args.config_json:
            json_config = json.loads(args.config_json, object_pairs_hook=OrderedDict)
            config = ordered_dict_merge(json_config, config)

        logger.debug('Resulting config: %s', json.dumps(config, indent=4))

        #
        # Start doing actual firewall stuff
        #
        with fwgen.Rollback(config) as fw:
            if args.clear:
                logger.warning('Clearing the firewall...')
                fw.clear()
                logger.warning('Firewall cleared!')
            elif args.restore:
                logger.info('Restoring ruleset...')
                fw.restore()
                logger.info('Ruleset restored!')
            else:
                logger.info('Applying ruleset...')
                fw.apply()
                logger.info('Ruleset applied!')

            if args.flush_connections:
                logger.info('Flushing connection tracking table...')
                fw.flush_connections()
                logger.info('Connection tracking table flushed!')

            logger.info('Running check commands...')
            fw.check()
            logger.info('Check commands OK!')

            if not args.no_confirm:
                logger.warning('\nRolling back in %d seconds unless confirmed. Verify '
                               'that you can establish NEW connections!', args.timeout)
                message = ("\n-> Press 'Enter' to confirm or 'Ctrl-C' to rollback immediately\n")
                wait_for_input(message, args.timeout)

            if not args.restore:
                if args.no_save:
                    logger.warning('Saving is disabled. The ruleset will not be persistent!')
                else:
                    logger.info('Saving ruleset...')
                    fw.save()
                    fw.service()
                    logger.info('Ruleset saved!')
    except TimeoutExpired:
        return 1
    except Exception as e:
        logger.debug(traceback.format_exc())
        logger.error(e)
        return 1

def main():
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        print('Aborted by user!')
        sys.exit(130)
