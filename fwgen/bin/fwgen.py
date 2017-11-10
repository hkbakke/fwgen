import argparse
import signal
import sys
import json
import logging
import traceback
from collections import OrderedDict
from subprocess import CalledProcessError
from pathlib import Path
from tempfile import mkstemp

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
    parser.add_argument('--clear', action='store_true', help='Clear the ruleset')
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
        fw = fwgen.FwGen(config)

        if not args.no_confirm:
            timeout = args.timeout or 20
            logger.info('\n*** Rolling back in %d seconds if not confirmed ***', timeout)

            # Create temp files for rollback
            ip_rollback = Path(mkstemp()[1])
            ip6_rollback = Path(mkstemp()[1])
            ipsets_rollback = Path(mkstemp()[1])

            # Save current firewall setup
            fw.save(ip_restore=ip_rollback, ip6_restore=ip6_rollback,
                    ipsets_restore=ipsets_rollback)

        if args.clear:
            logger.warning('Reset is enabled. The ruleset will be cleared!')
            fw.clear()
        else:
            fw.apply()

        if args.flush_connections:
            fw.flush_connections()

        if not args.no_confirm:
            message = ("\nThe ruleset has been applied successfully! Verify that you can "
                       "establish NEW connections!\n\n-> Press 'Enter' to confirm or "
                       "'Ctrl-C' to rollback immediately")

            try:
                wait_for_input(message, timeout)
            except (TimeoutExpired, KeyboardInterrupt):
                logger.warning('\nNo confirmation received. Rolling back...')
                fw.rollback()
                return 1
            finally:
                # Remove rollback files
                ip_rollback.unlink()
                ip6_rollback.unlink()
                ipsets_rollback.unlink()

        if args.no_save:
            logger.warning('Saving is disabled. The ruleset will not be persistent!')
        else:
            fw.save()
            fw.write_restore_script()
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
