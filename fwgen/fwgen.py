import re
import subprocess
import logging
import shutil
import shlex
import ipaddress
import difflib
import textwrap
import os
import tarfile
from datetime import datetime
from collections import OrderedDict
from pathlib import Path
from operator import attrgetter

from fwgen.helpers import ordered_dict_merge, random_word, run_command


LOGGER = logging.getLogger(__name__)
DEFAULT_CHAINS = {
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'nat': ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'raw': ['PREROUTING', 'OUTPUT'],
    'security': ['INPUT', 'FORWARD', 'OUTPUT']
}


class InvalidChain(Exception):
    pass


class RulesetError(Exception):
    pass


class DeprecationError(Exception):
    pass


class NonExistingArchiveError(Exception):
    pass


class Ruleset(object):
    def __init__(self):
        self.save_cmd = None
        self.restore_cmd = None
        self.restore_file = None
        self.ruleset_type = None

    def apply(self, rules):
        LOGGER.debug("Applying %s rules", self.ruleset_type)
        self._apply(rules)

    def _apply(self, rules):
        data = '%s\n' % '\n'.join(rules)
        p = subprocess.Popen(self.restore_cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE,
                             universal_newlines=True)
        stderr = p.communicate(data)[1]
        if p.returncode != 0:
            raise RulesetError(stderr)

    def restore(self, path=None):
        path = path or self.restore_file
        LOGGER.debug("Restoring %s rules from '%s'", self.ruleset_type, path)
        self.apply(self._get_restore_rules(path))

    @staticmethod
    def _get_restore_rules(path):
        with path.open('r') as f:
            return f.readlines()

    def save(self, path):
        LOGGER.debug("Saving %s rules to '%s'", self.ruleset_type, path)
        self._save(path)

    def _save(self, path):
        try:
            path.parent.mkdir(parents=True)
        except FileExistsError:
            pass

        tmp = path.parent / Path(str(path.name) + '.tmp')
        LOGGER.debug("Running command '%s > %s'", ' '.join(self.save_cmd), tmp)
        with os.fdopen(os.open(str(tmp), os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
            subprocess.check_call(self.save_cmd, stdout=f)

        LOGGER.debug("Renaming '%s' to '%s'", tmp, path)
        tmp.rename(path)
        self.restore_file = path

    def running(self):
        output = run_command(self.save_cmd)
        return output.splitlines()

    @staticmethod
    def _diff_filter(diff):
        for i in diff:
            yield i

    def diff(self, rules, reverse=False):
        if reverse:
            old = self._diff_filter(self.running())
            new = self._diff_filter(rules)
        else:
            old = self._diff_filter(rules)
            new = self._diff_filter(self.running())

        return difflib.unified_diff(list(old), list(new), lineterm='')


class IptablesCommon(Ruleset):
    def clear(self):
        LOGGER.debug("Clearing %s rules", self.ruleset_type)
        rules = []
        for table, chains in DEFAULT_CHAINS.items():
            rules.append('*%s' % table)
            for chain in chains:
                rules.append(':%s %s' % (chain, 'ACCEPT'))
            rules.append('COMMIT')
        self._apply(rules)

    @staticmethod
    def _diff_filter(diff):
        """
        Get rid of counters and commented lines with timestamps.
        """
        counters_regex = re.compile(r'(:.+)\[[0-9]+:[0-9]+\]$')

        for i in diff:
            if i.startswith('#'):
                continue

            counters_match = re.search(counters_regex, i)
            if counters_match:
                i = counters_match.group(1)

            yield i


class Iptables(IptablesCommon):
    def __init__(self, iptables_save='iptables-save', iptables_restore='iptables-restore'):
        super().__init__()
        self.save_cmd = [iptables_save]
        self.restore_cmd = [iptables_restore]
        self.ruleset_type = 'iptables'


class Ip6tables(IptablesCommon):
    def __init__(self, ip6tables_save='ip6tables-save', ip6tables_restore='ip6tables-restore'):
        super().__init__()
        self.save_cmd = [ip6tables_save]
        self.restore_cmd = [ip6tables_restore]
        self.ruleset_type = 'ip6tables'


class Ipsets(Ruleset):
    def __init__(self, ipset='ipset'):
        super().__init__()
        self.ipset = ipset
        self.save_cmd = [ipset, 'save']
        self.restore_cmd = [ipset, 'restore']
        self.ruleset_type = 'ipset'

    def list(self):
        output = run_command([self.ipset, 'list', '-name'])
        return output.splitlines()

    def clear(self):
        LOGGER.debug("Clearing %s rules", self.ruleset_type)
        self._apply(['flush', 'destroy'])

    @staticmethod
    def _get_ipset_tmp_name(ipset):
        return '%s.%s' % (ipset, random_word(3))

    def apply(self, rules):
        LOGGER.debug("Applying %s rules", self.ruleset_type)
        current_ipsets = self.list()
        output = []
        tmp_ipsets = {}
        cur = None

        for rule in rules:
            ipset = rule.split(maxsplit=2)[1]
            if ipset in current_ipsets:
                if ipset != cur:
                    tmp = self._get_ipset_tmp_name(ipset)
                    while tmp in current_ipsets:
                        tmp = self._get_ipset_tmp_name(ipset)
                    tmp_ipsets[ipset] = tmp
                output.append(rule.replace(ipset, tmp_ipsets[ipset], 1))
            else:
                output.append(rule)
            cur = ipset

        for ipset, tmp in tmp_ipsets.items():
            output.append('swap %s %s' % (tmp, ipset))
            output.append('destroy %s' % tmp)

        # Remove any leftover ipsets that we no longer need.
        # List sets causes errors if the referenced ipsets are removed before the
        # list set. To avoid this we need to flush the ipsets before we can destroy
        # them, so we need two passes.
        destroy = [i for i in current_ipsets if i not in tmp_ipsets]

        for ipset in destroy:
            output.append('flush %s' % ipset)

        for ipset in destroy:
            output.append('destroy %s' % ipset)

        self._apply(output)

    @staticmethod
    def _diff_filter(diff):
        """
        Ipset seems to add entries in a non-deterministic order when doing
        atomic replace. This will cause the differ to output changes even
        when there are none. To fix this, ensure the entries for each ipset
        is sorted before being diffed.
        """
        entries = []

        for i in diff:
            if i.startswith('add '):
                entries.append(i)
                continue

            for entry in sorted(entries):
                yield entry

            entries = []
            yield i

        # Ensure we get the last content if the in_data ends in 'add'-entries
        for entry in sorted(entries):
            yield entry


class ConfigDir(object):
    def __init__(self, dirname):
        self.dirname = dirname
        self.config = self.dirname / 'config.yml'
        self.example_config = Path(__file__).parent / 'doc' / 'examples' / 'config.yml'

    def create(self):
        LOGGER.info("Ensuring '%s' exists...", self.dirname)

        try:
            self.dirname.mkdir(parents=True)
        except FileExistsError:
            pass

        if not self.config.is_file():
            LOGGER.info("Config file does not exist. Adding empty example config.\n"
                        "Please edit '%s' before you run fwgen.", self.config)
            shutil.copyfile(str(self.example_config), str(self.config))

        LOGGER.info("Setting permissions on '%s'", self.config)
        self.config.chmod(0o600)


class Archive(object):
    def __init__(self, path):
        self.path = path
        self.suffix = '.tar.xz'
        self.tmp_suffix = '.tmp'

    def create(self):
        try:
            self.path.mkdir(parents=True)
        except FileExistsError:
            pass

    def new(self):
        timestamp = datetime.now().strftime('%Y%m%dT%H%M%S')
        path = self.path / Path('%s%s' % (timestamp, self.suffix))
        return ArchiveFile(path)

    def get_all(self):
        for path in self.path.glob('*%s' % self.suffix):
            yield ArchiveFile(path)

    def get_all_indexed(self):
        archive_files = sorted(self.get_all(), key=attrgetter('name'), reverse=True)
        for index, archive_file in enumerate(archive_files):
            yield (index, archive_file)

    def clean(self, keep=0):
        if keep < 0:
            raise ValueError('keep value must be an integer 0 or more')

        for tmp in self.path.glob('*%s' % self.tmp_suffix):
            tmp.unlink()

        archive_files = sorted(self.get_all(), key=attrgetter('name'), reverse=True)
        for archive_file in archive_files[keep:]:
            archive_file.remove()

    def get_by_index(self, index):
        """
        The archive files must be sorted the same way as the 'archive --list' output
        to ensure identical index mapping
        """
        for i, archive_file in self.get_all_indexed():
            if i == index:
                return archive_file
        raise NonExistingArchiveError("The archive file index '%d' does not exist" % index)

    def get_by_name(self, name):
        for archive_file in self.get_all():
            if archive_file.name == name:
                return archive_file
        raise NonExistingArchiveError("The archive file named '%s' does not exist" % name)

    def get(self, name):
        try:
            index = int(name)
            return self.get_by_index(index)
        except ValueError:
            pass

        return self.get_by_name(name)


class ArchiveFile(object):
    def __init__(self, path):
        self.path = path
        self.name = path.name
        self.iptables_restore = 'iptables.restore'
        self.ip6tables_restore = 'ip6tables.restore'
        self.ipsets_restore = 'ipsets.restore'

    def add(self, iptables, ip6tables, ipsets):
        tmp = Path(str(self.path) + '.tmp')

        LOGGER.debug("Archiving ruleset to '%s'", tmp)
        with os.fdopen(os.open(str(tmp), os.O_WRONLY | os.O_CREAT, 0o600), 'wb') as f:
            with tarfile.open(mode='w:xz', fileobj=f) as tar:
                tar.add(str(iptables), arcname=self.iptables_restore)
                tar.add(str(ip6tables), arcname=self.ip6tables_restore)
                tar.add(str(ipsets), arcname=self.ipsets_restore)

        LOGGER.debug("Renaming '%s' to '%s'", tmp, self.path)
        tmp.rename(self.path)

    def remove(self):
        LOGGER.debug("Removing ruleset archive '%s'", self.path)
        self.path.unlink()

    def _extract_file(self, name):
        with tarfile.open(str(self.path), 'r:xz') as tar:
            with tar.extractfile(name) as f:
                return f.read().decode('utf-8').splitlines()

    def iptables(self):
        return self._extract_file(self.iptables_restore)

    def ip6tables(self):
        return self._extract_file(self.ip6tables_restore)

    def ipsets(self):
        return self._extract_file(self.ipsets_restore)


class FwGen(object):
    def __init__(self, config):
        defaults = OrderedDict()
        defaults = {
            'restore_files': {
                'iptables': '/var/lib/fwgen/rules/iptables.restore',
                'ip6tables': '/var/lib/fwgen/rules/ip6tables.restore',
                'ipsets': '/var/lib/fwgen/rules/ipsets.restore'
            },
            'cmds': {
                'iptables_save': 'iptables-save',
                'iptables_restore': 'iptables-restore',
                'ip6tables_save': 'ip6tables-save',
                'ip6tables_restore': 'ip6tables-restore',
                'ipset': 'ipset'
            },
            'archive': {
                'path': '/var/lib/fwgen/archive',
                'keep': 10
            },
            'check_commands': []
        }
        self.config = ordered_dict_merge(config, defaults)
        self._deprecation_check()
        self.iptables = Iptables(self.config['cmds']['iptables_save'],
                                 self.config['cmds']['iptables_restore'])
        self.ip6tables = Ip6tables(self.config['cmds']['ip6tables_save'],
                                   self.config['cmds']['ip6tables_restore'])
        self.ipsets = Ipsets(self.config['cmds']['ipset'])
        self.restore_file = {
            'ip': Path(self.config['restore_files']['iptables']),
            'ip6': Path(self.config['restore_files']['ip6tables']),
            'ipset': Path(self.config['restore_files']['ipsets'])
        }
        self.zone_pattern = re.compile(r'^(.*?)%\{(.+?)\}(.*)$')
        self.object_pattern = re.compile(r'^(.*?)\$\{(.+?)\}(.*)$')
        self._archive = Archive(Path(self.config['archive']['path']))

    def _deprecation_check(self):
        if self.config.get('global'):
            raise DeprecationError("The dictionary 'global' is no longer valid in "
                                   "v0.10.0 and newer configurations. Move existing "
                                   "contents to the top level in the configuration.")
        if self.config.get('rules'):
            raise DeprecationError("The dictionary 'rules' is no longer valid in "
                                   "v0.11.0 and newer configurations. Move existing "
                                   "contents to the top level in the configuration.")
        if self.config.get('variables'):
            raise DeprecationError("The dictionary 'variables' is renamed to 'objects'"
                                   " in v0.14.0 and newer configurations.")

    def _output_ipsets(self):
        output = []
        for ipset, params in self.config.get('ipsets', {}).items():
            create_cmd = ['create %s %s' % (ipset, params['type'])]
            create_cmd.append(params.get('options', None))
            output.append(' '.join([i for i in create_cmd if i]))
            for entry in params['entries']:
                output.extend(self._expand_objects('add %s %s' % (ipset, entry), ruletype='ipset'))
        return output

    def _get_policy_rules(self):
        for table, chains in DEFAULT_CHAINS.items():
            for chain in chains:
                policy = 'ACCEPT'
                try:
                    policy = self.config['policy'][table][chain]
                except KeyError:
                    pass
                yield (table, ':%s %s' % (chain, policy))

    def _get_zone_id(self, zone):
        return list(self.config.get('zones', {}).keys()).index(zone)

    def _get_zone_rules(self):
        for zone, params in self.config.get('zones', {}).items():
            if zone == 'local':
                yield from self._create_local_zone(zone, params.get('rules', {}))
            else:
                yield from self._create_zone(zone, params.get('rules', {}))

    def _get_helper_chains(self):
        rules = {}
        try:
            rules = self.config['helper_chains']
        except KeyError:
            pass

        for table, chains in rules.items():
            for chain in chains:
                yield (table, self._new_chain(chain))

        for rule in self._get_rules(rules):
            yield rule

    @staticmethod
    def _get_rules(rules):
        for table, chains in rules.items():
            for chain, chain_rules in chains.items():
                for rule in chain_rules:
                    yield (table, '-A %s %s' % (chain, rule))

    @staticmethod
    def _new_chain(chain):
        return ':%s -' % chain

    def _create_zone_forward(self, zone, target):
        chain = 'FORWARD'
        yield from self._create_zone_in(zone, chain, target)

        # Accept intra-zone traffic
        comment = 'Intra-zone'
        yield '-A %s -o %%{%s} -m comment --comment "%s" -j ACCEPT' % (target, zone, comment)

    def _create_zone_in(self, zone, chain, target, comment=None):
        yield self._new_chain(target)
        if comment:
            yield '-A %s -i %%{%s} -m comment --comment "%s" -j %s' % (chain, zone, comment, target)
        else:
            yield '-A %s -i %%{%s} -j %s' % (chain, zone, target)

    def _create_zone_out(self, zone, chain, target, comment=None):
        yield self._new_chain(target)
        if comment:
            yield '-A %s -o %%{%s} -m comment --comment "%s" -j %s' % (chain, zone, comment, target)
        else:
            yield '-A %s -o %%{%s} -j %s' % (chain, zone, target)

    def _create_to_zones(self, zone, to_zones):
        zone_id = self._get_zone_id(zone)
        zone_chain_name = 'zone%d' % zone_id
        target = '%s_FORWARD' % zone_chain_name
        yield from self._create_zone_forward(zone, target)

        for to_zone, rules in to_zones.items():
            if to_zone == 'local':
                to_target = '%s_to_%s' % (zone_chain_name, to_zone)
                comment = '%s -> %s' % (zone, to_zone)
                yield from self._create_zone_in(zone, 'INPUT', to_target, comment)
            else:
                to_zone_id = self._get_zone_id(to_zone)
                to_zone_chain_name = 'zone%d' % to_zone_id
                to_target = '%s_to_%s' % (zone_chain_name, to_zone_chain_name)
                comment = '%s -> %s' % (zone, to_zone)
                yield from self._create_zone_out(to_zone, target, to_target, comment)

            for rule in rules:
                yield '-A %s %s' % (to_target, rule)

    def _create_local_zone(self, zone, rules):
        for table, chains in rules.items():
            for chain in chains:
                if chain == 'to':
                    for to_zone, to_zone_rules in chains['to'].items():
                        to_zone_id = self._get_zone_id(to_zone)
                        target = '%s_to_zone%d' % (zone, to_zone_id)
                        comment = '%s -> %s' % (zone, to_zone)
                        for rule in self._create_zone_out(to_zone, 'OUTPUT', target, comment):
                            yield (table, rule)

                        for rule in to_zone_rules:
                            yield (table, '-A %s %s' % (target, rule))
                else:
                    raise InvalidChain("'%s' is not a valid target chain" % chain)

    def _create_zone(self, zone, rules):
        # Normalize zone name to avoid being restricted by max chain name length
        zone_id = self._get_zone_id(zone)
        zone_chain_name = 'zone%d' % zone_id
        LOGGER.debug("Zone ID for zone '%s': %d", zone, zone_id)

        for table, chains in rules.items():
            for chain, items in chains.items():
                target = '%s_%s' % (zone_chain_name, chain)

                if chain in ['PREROUTING', 'INPUT']:
                    for rule in self._create_zone_in(zone, chain, target):
                        yield (table, rule)
                elif chain == 'FORWARD':
                    for rule in self._create_zone_forward(zone, target):
                        yield (table, rule)
                elif chain == 'to':
                    for i in ['INPUT', 'FORWARD', 'OUTPUT']:
                        if i in chains:
                            raise InvalidChain("Error in zone '%s': '%s' can not be combined "
                                               "with '%s'" % (zone, i, chain))

                    for rule in self._create_to_zones(zone, items):
                        yield (table, rule)
                elif chain in ['OUTPUT', 'POSTROUTING']:
                    for rule in self._create_zone_out(zone, chain, target):
                        yield (table, rule)
                else:
                    raise InvalidChain("'%s' is not a valid target chain" % chain)

                if isinstance(items, list):
                    for rule in items:
                        yield (table, '-A %s %s' % (target, rule))

    def _expand_zones(self, rule):
        match = re.search(self.zone_pattern, rule)
        if match:
            zone = match.group(2)

            for interface in self.config['zones'][zone]['interfaces']:
                rule_expanded = '%s%s%s' % (match.group(1), interface, match.group(3))

                for rule_ in self._expand_zones(rule_expanded):
                    yield rule_
        else:
            yield rule

    @staticmethod
    def _has_option(rule, option):
        if (rule.startswith('%s ' % option)
                or ' %s ' % option in rule
                or rule.endswith(' %s' % option)):
            return True
        return False

    def _is_ipv4_rule(self, rule):
        return bool(self._has_option(rule, '-4'))

    def _is_ipv6_rule(self, rule):
        return bool(self._has_option(rule, '-6'))

    @staticmethod
    def _is_ipv4_addr(string):
        try:
            ipaddress.IPv4Network(string)
            return True
        except ipaddress.AddressValueError:
            return False

    @staticmethod
    def _is_ipv6_addr(string):
        try:
            ipaddress.IPv6Network(string)
            return True
        except ipaddress.AddressValueError:
            return False

    def _expand_objects(self, string, ruletype='iptables'):
        match = re.search(self.object_pattern, string)
        if match:
            values = self.config['objects'][match.group(2)]

            if not isinstance(values, list):
                values = [values]

            for value in values:
                string_expanded = '%s%s%s' % (match.group(1), value, match.group(3))

                # Only try to be smart if the rule is not already tagged as a IPv4 or IPv6 rule
                if ruletype == 'iptables':
                    if self._is_ipv4_addr(value):
                        if self._is_ipv6_rule(string_expanded):
                            continue

                        if not self._is_ipv4_rule(string_expanded):
                            string_expanded = '-4 %s' % string_expanded
                    elif self._is_ipv6_addr(value):
                        if self._is_ipv4_rule(string_expanded):
                            continue

                        if not self._is_ipv6_rule(string_expanded):
                            string_expanded = '-6 %s' % string_expanded

                for string_ in self._expand_objects(string_expanded):
                    yield string_
        else:
            yield string

    def _parse_rule(self, rule):
        for rule_ in self._expand_objects(rule):
            for rule_expanded in self._expand_zones(rule_):
                yield rule_expanded

    def _output_rules(self, rules):
        output = []
        for table in DEFAULT_CHAINS:
            output.append('*%s' % table)
            for rule_table, rule in rules:
                if rule_table == table:
                    for rule_parsed in self._parse_rule(rule):
                        output.append(rule_parsed)
            output.append('COMMIT')
        return output

    def save(self):
        self.iptables.save(self.restore_file['ip'])
        self.ip6tables.save(self.restore_file['ip6'])
        self.ipsets.save(self.restore_file['ipset'])

    def archive(self):
        keep = self.config['archive']['keep']
        self._archive.create()

        if keep < 1:
            self._archive.clean(keep)
            return

        archive_file = self._archive.new()
        archive_file.add(self.restore_file['ip'], self.restore_file['ip6'],
                         self.restore_file['ipset'])
        self._archive.clean(keep)

    def restore_archived(self, name):
        archive_file = self._archive.get(name)
        iptables = archive_file.iptables()
        ip6tables = archive_file.ip6tables()
        ipsets = archive_file.ipsets()
        LOGGER.info("Restoring ruleset from '%s'", archive_file.path)
        self._apply(iptables, ip6tables, ipsets)

    def restore(self):
        iptables = self.restore_file['ip']
        ip6tables = self.restore_file['ip6']
        ipsets = self.restore_file['ipset']
        LOGGER.info('Restoring from saved ruleset')
        self.iptables.restore(iptables)
        self.ip6tables.restore(ip6tables)
        self.ipsets.restore(ipsets)

    def _apply(self, ip_rules, ip6_rules, ipsets):
        # Apply ipsets first to ensure they exist when the rules are applied
        try:
            self.ipsets.apply(ipsets)
        except RulesetError as e:
            LOGGER.debug(str(e))
            LOGGER.warning('The changes to the ipset configuration is not compatible with'
                           ' atomic updating. The firewall will be temporary cleared!')
            self.clear()
            self.ipsets.apply(ipsets)

        self.iptables.apply(ip_rules)
        self.ip6tables.apply(ip6_rules)

    def apply(self):
        rules = []
        rules.extend(self._get_policy_rules())
        rules.extend(self._get_helper_chains())
        rules.extend(self._get_rules(self.config.get('pre_default', {})))
        rules.extend(self._get_rules(self.config.get('default', {})))
        rules.extend(self._get_rules(self.config.get('pre_zone', {})))
        rules.extend(self._get_zone_rules())
        iptables_rules = self._output_rules(rules)
        LOGGER.debug('\n'.join(iptables_rules))
        self._apply(iptables_rules, iptables_rules, self._output_ipsets())

    def clear(self):
        # Clear ipsets after the iptables rules to ensure ipsets are not in use
        self.iptables.clear()
        self.ip6tables.clear()
        self.ipsets.clear()

    @staticmethod
    def _printable_diff(diff, header, indent=4):
        content = '\n'.join(diff)
        if not content:
            return ''
        return '%s\n\n%s\n' % (header, textwrap.indent(content, ' ' * indent))

    def _diff(self, iptables, ip6tables, ipsets, reverse=False):
        ipt_diff = self.iptables.diff(iptables, reverse)
        ip6t_diff = self.ip6tables.diff(ip6tables, reverse)
        ipsets_diff = self.ipsets.diff(ipsets, reverse)
        ipt_diff_output = self._printable_diff(ipt_diff, 'iptables changes:')
        ip6t_diff_output = self._printable_diff(ip6t_diff, 'ip6tables changes:')
        ipsets_diff_output = self._printable_diff(ipsets_diff, 'ipsets changes:')
        return ipt_diff_output + ip6t_diff_output + ipsets_diff_output

    def diff_archive(self, name):
        archive_file = self._archive.get(name)
        ipt = archive_file.iptables()
        ip6t = archive_file.ip6tables()
        ipsets = archive_file.ipsets()
        return self._diff(ipt, ip6t, ipsets, reverse=True)

    def list_archive(self):
        return self._archive.get_all_indexed()

    def running_iptables(self):
        return self.iptables.running()

    def running_ip6tables(self):
        return self.ip6tables.running()

    def running_ipsets(self):
        return self.ipsets.running()


class Rollback(FwGen):
    def __init__(self, config):
        super().__init__(config)
        self.ip_rollback = None
        self.ip6_rollback = None
        self.ipsets_rollback = None

    def __enter__(self):
        self.ip_rollback = self.iptables.running()
        self.ip6_rollback = self.ip6tables.running()
        self.ipsets_rollback = self.ipsets.running()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        if exc_type:
            LOGGER.warning('Rolling back...')
            self.rollback()

    def check(self):
        for cmd in self.config['check_commands']:
            run_command(shlex.split(cmd))

    def diff(self):
        ipt_old = self.ip_rollback
        ip6t_old = self.ip6_rollback
        ipsets_old = self.ipsets_rollback
        return self._diff(ipt_old, ip6t_old, ipsets_old)

    def rollback(self):
        self._apply(self.ip_rollback, self.ip6_rollback, self.ipsets_rollback)
