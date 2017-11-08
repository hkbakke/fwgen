import argparse
import signal
import sys
import json
import logging
from collections import OrderedDict
from subprocess import CalledProcessError
from pathlib import Path
from tempfile import mkstemp

import yaml
from fwgen import fwgen
from fwgen.helpers import ordered_dict_merge, create_config_dir


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
    parser.add_argument('--create-config-dir', metavar='PATH', nargs='?',
                        const='__default__', help='Create initial config dir')
    parser.add_argument('--config', metavar='PATH', default='/etc/fwgen/config.yml',
                        help='Override path to config file')
    parser.add_argument('--defaults', metavar='PATH',
                        default=str(Path(fwgen.__file__).parent / 'etc/defaults.yml'),
                        help='Override path to defaults file')
    parser.add_argument('--config-json', metavar='JSON', help='JSON formatted config')
    parser.add_argument('--with-reset', action='store_true',
                        help='Clear the firewall before reapplying. Recommended only if ipsets '
                             'in use are preventing you from applying the new configuration.')
    parser.add_argument('--no-save', action='store_true',
                        help='Apply the ruleset but do not make it persistent')
    parser.add_argument('--flush-connections', action='store_true',
                        help='Flush all connections after applying ruleset')
    parser.add_argument('--reset', action='store_true', help='Clear the ruleset')
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

    if args.create_config_dir:
        if args.create_config_dir == '__default__':
            config_dir = None
        else:
            config_dir = args.create_config_dir

        create_config_dir(config_dir)
        return 0

    #
    # Configuration merge order. Each merge overrides the previous one if a parameter
    # is provided in both configurations.
    #
    #   1. config from defaults file
    #   2. config from config file
    #   3. config provided at runtime via --config-json
    #
    try:
        logger.debug("Using defaults file '%s'", args.defaults)
        with open(args.defaults, 'r') as f:
            config = yaml_load_ordered(f) or {}
    except FileNotFoundError as e:
        logger.error(str(e))
        return 3

    try:
        logger.debug("Using config file '%s'", args.config)
        with open(args.config, 'r') as f:
            user_config = yaml_load_ordered(f) or {}
            config = ordered_dict_merge(user_config, config)
    except FileNotFoundError as e:
        if args.config_json:
            logger.warning("'%s' not found. You will loose connectivity if your json config "
                           "is incomplete!", args.config)
        else:
            logger.error(str(e))
            return 3

    if args.config_json:
        json_config = json.loads(args.config_json, object_pairs_hook=OrderedDict)
        config = ordered_dict_merge(json_config, config)

    logger.debug('Resulting config: %s', json.dumps(config, indent=4))

    #
    # Start doing actual firewall stuff
    #
    fw = fwgen.FwGen(config)

    if args.no_save:
        logger.warning('Saving is disabled. The ruleset will not be persistent!')

    if args.reset:
        logger.warning('Reset is enabled. The ruleset will be cleared!')

    try:
        if not args.no_confirm:
            timeout = args.timeout or 20
            logger.info('\n*** Rolling back in %d seconds if not confirmed ***', timeout)

            # Create temp files for rollback
            ip_rollback = Path(mkstemp()[1])
            ip6_rollback = Path(mkstemp()[1])
            ipsets_rollback = Path(mkstemp()[1])

            # Save current firewall setup
            fw.save(external_ipsets=True, ip_restore=ip_rollback, ip6_restore=ip6_rollback,
                    ipsets_restore=ipsets_rollback)

        if args.reset or args.with_reset:
            fw.reset()

        if not args.reset:
            fw.apply(args.flush_connections)

        if not args.no_confirm:
            message = ('\nThe ruleset has been applied successfully! Press \'Enter\' to confirm.')

            try:
                wait_for_input(message, timeout)
            except (TimeoutExpired, KeyboardInterrupt):
                logger.warning('\nNo confirmation received. Rolling back...')

                # Restore previous firewall setup
                fw.reset()
                fw.restore(ip_restore=ip_rollback, ip6_restore=ip6_rollback,
                           ipsets_restore=ipsets_rollback)
                return 4
            finally:
                # Remove rollback files
                ip_rollback.unlink()
                ip6_rollback.unlink()
                ipsets_rollback.unlink()

        if not args.no_save:
            fw.save()
            fw.write_restore_script()
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
