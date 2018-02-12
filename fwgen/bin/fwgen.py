import argparse
import signal
import sys
import json
import logging
import traceback
from collections import OrderedDict
from pathlib import Path

from fwgen import fwgen, __version__
from fwgen.helpers import yaml_load_ordered, ordered_dict_merge


LOGGER = logging.getLogger()


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

def merge_config(defaults_file, config_file, config_json=None):
    """
    Configuration merge order. Each merge overrides the previous one if a parameter
    is provided in both configurations.

        1. config from defaults file
        2. config from config file
        3. config provided at runtime via --config-json
    """
    LOGGER.debug("Loading defaults file '%s'", defaults_file)
    with open(defaults_file, 'r') as f:
        config = yaml_load_ordered(f) or {}

    LOGGER.debug("Loading config file '%s'", config_file)
    try:
        with open(config_file, 'r') as f:
            user_config = yaml_load_ordered(f) or {}
        config = ordered_dict_merge(user_config, config)
    except FileNotFoundError:
        if config_json is None:
            raise
        LOGGER.warning("Config file '%s' not found. All non-default settings must "
                       "be fed via '--config-json'", config_file)

    if config_json is not None:
        json_config = json.loads(config_json, object_pairs_hook=OrderedDict)
        config = ordered_dict_merge(json_config, config)

    return config

def archive_subcommands(args, config):
    fw = fwgen.FwGen(config)

    if args.diff:
        diff = fw.diff_archive(args.diff)
        if diff:
            print(diff)
    else:
        archive_files_indexed = list(fw.list_archive())
        width = max(len(str(len(archive_files_indexed))), len('INDEX'))
        print('%s\tNAME' % 'INDEX'.ljust(width))
        for index, archive_file in archive_files_indexed:
            print('%s\t%s' % (str(index).ljust(width), archive_file.name))
    return 0

def config_subcommands(args, config):
    print(json.dumps(config, indent=4))
    return 0

def running_subcommands(args, config):
    fw = fwgen.FwGen(config)
    selection = args.select

    if not selection:
        selection = 'all'

    if selection in ['ipsets', 'all']:
        print('#\n#\n# IPSETS\n#')
        print('\n'.join(fw.running_ipsets()))
    if selection in ['iptables', 'fw', 'fw4', 'all']:
        print('#\n#\n# IPTABLES\n#')
        print('\n'.join(fw.running_iptables()))
    if selection in ['ip6tables', 'fw', 'fw6', 'all']:
        print('#\n#\n# IP6TABLES\n#')
        print('\n'.join(fw.running_ip6tables()))
    return 0

def apply_subcommands(args, config):
    with fwgen.Rollback(config) as fw:
        if args.clear:
            LOGGER.warning('Clearing the firewall...')
            fw.clear()
            LOGGER.warning('Firewall cleared!')
        elif args.restore:
            fw.restore()
            LOGGER.info('Ruleset restored!')
        elif args.archive:
            fw.restore_archived(args.archive)
        else:
            LOGGER.info('Applying ruleset...')
            fw.apply()
            LOGGER.info('Ruleset applied!')

        if not args.no_diff:
            diff = fw.diff()
            if diff:
                LOGGER.info(diff)

        LOGGER.info('Running check commands...')
        fw.check()
        LOGGER.info('Check commands OK!')

        if not args.no_confirm:
            LOGGER.warning('Rolling back in %d seconds unless confirmed. Verify that you '
                           'can establish NEW connections!', args.timeout)
            message = ("\n>>> Press 'Enter' to confirm or 'Ctrl-C' to rollback immediately\n")
            wait_for_input(message, args.timeout)

        if args.no_save:
            LOGGER.warning('Saving is disabled. The ruleset will not be persistent!')
        else:
            LOGGER.info('Saving ruleset...')
            fw.save()
            if not args.no_archive:
                fw.archive()
            LOGGER.info('Ruleset saved!')

def _main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--create-config-dir', metavar='PATH', default=False, nargs='?',
                        const=Path('/etc/fwgen'), help='Create initial config dir')
    parser.add_argument('--config', metavar='PATH', default='/etc/fwgen/config.yml',
                        help='Override path to config file')
    parser.add_argument('--defaults', metavar='PATH',
                        default=str(Path(fwgen.__file__).parent / 'etc/defaults.yml'),
                        help='Override path to defaults file')
    parser.add_argument('--config-json', metavar='JSON', default=None,
                        help='JSON formatted config')
    parser.add_argument('--version', action='store_true', help='Show version')
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
    subparsers = parser.add_subparsers(title='subcommands', dest='subcommand')

    # apply commands subparser
    apply_parser = subparsers.add_parser('apply', help='apply firewall settings')
    apply_parser.add_argument('--no-diff', action='store_true', help='Do not show diff on changes')
    apply_parser.add_argument('--no-archive', action='store_true',
                              help='Do not archive the saved ruleset')
    apply_parser.add_argument('--no-save', action='store_true',
                              help='Apply the ruleset but do not make it persistent. This also '
                                   'includes archiving.')
    apply_mutex_1 = apply_parser.add_mutually_exclusive_group()
    apply_mutex_1.add_argument('--clear', action='store_true', help='Clear the ruleset')
    apply_mutex_1.add_argument('--restore', action='store_true', default=False,
                               help='Restore saved ruleset')
    apply_mutex_1.add_argument('--archive', metavar='ARCHIVE',
                               help='Restore archived ruleset')
    apply_mutex_2 = apply_parser.add_mutually_exclusive_group()
    apply_mutex_2.add_argument('--timeout', metavar='SECONDS', type=int, default=20,
                               help='Override timeout for rollback')
    apply_mutex_2.add_argument('--no-confirm', action='store_true',
                               help="Don't ask for confirmation before storing ruleset")
    apply_parser.set_defaults(func=apply_subcommands)

    # show commands subparser
    show_parser = subparsers.add_parser('show', help='show configuration')
    show_subparsers = show_parser.add_subparsers(title='subcommands')

    # archive subparser
    archive_parser = show_subparsers.add_parser('archive', help='show archive')
    archive_parser.add_argument('diff', metavar='INDEX|NAME', nargs='?',
                                help='Show differences between running and archived ruleset')
    archive_parser.set_defaults(func=archive_subcommands)

    # config subparser
    config_parser = show_subparsers.add_parser('config', help='show fwgen configuration')
    config_parser.set_defaults(func=config_subcommands)

    # running subparser
    running_parser = show_subparsers.add_parser('running', help='show running configuration')
    running_parser.add_argument(
        'select',
        nargs='?',
        choices=[
            'iptables',
            'fw4',
            'ip6tables',
            'fw6',
            'fw',
            'ipsets',
            'all',
        ],
        help='Show specific configuration'
    )
    running_parser.set_defaults(func=running_subcommands)

    args = parser.parse_args()

    # Set up logging
    LOGGER.setLevel(args.log_level.upper())
    fmt = logging.Formatter('%(message)s')
    console = logging.StreamHandler()
    console.setFormatter(fmt)
    LOGGER.addHandler(console)

    try:
        if args.version:
            print('fwgen v%s' % __version__)
            return 0

        if args.create_config_dir is not False:
            configdir = fwgen.ConfigDir(Path(args.create_config_dir))
            configdir.create()
            return 0

        # Print help if no default function is defined
        try:
            getattr(args, 'func')
        except AttributeError:
            if args.subcommand == 'show':
                show_parser.print_help()
            else:
                parser.print_help()
            return 1

        config = merge_config(args.defaults, args.config, args.config_json)
        LOGGER.debug('Resulting config: %s', json.dumps(config, indent=4))

        args.func(args, config)
    except TimeoutExpired:
        return 1
    except Exception as e:
        LOGGER.debug(traceback.format_exc())
        LOGGER.error(e)
        return 1

    return 0

def main():
    try:
        sys.exit(_main())
    except KeyboardInterrupt:
        print('Aborted by user!')
        sys.exit(130)
