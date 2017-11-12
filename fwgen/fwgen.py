import re
import subprocess
import logging
from collections import OrderedDict
from pathlib import Path
from shutil import copyfile

from fwgen.helpers import ordered_dict_merge, get_etc, random_word


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
        data = ('%s\n' % '\n'.join(rules)).encode('utf-8')
        p = subprocess.Popen(self.restore_cmd, stdin=subprocess.PIPE, stderr=subprocess.PIPE)
        _, stderr = p.communicate(data)
        if p.returncode != 0:
            raise RulesetError(stderr.decode('utf-8'))

    def save(self, path):
        LOGGER.debug("Saving %s rules to '%s'", self.ruleset_type, path)
        self._save(path)

    def _save(self, path):
        try:
            path.parent.mkdir(parents=True)
        except FileExistsError:
            pass

        tmp = path.with_suffix('.tmp')
        with tmp.open('wb') as f:
            subprocess.check_call(self.save_cmd, stdout=f)
        tmp.chmod(0o600)
        tmp.rename(path)
        self.restore_file = path

    def running(self):
        output = subprocess.check_output(self.save_cmd, universal_newlines=True)
        return output.splitlines()


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


class Iptables(IptablesCommon):
    def __init__(self, iptables_save='iptables-save', iptables_restore='iptables-restore'):
        super().__init__()
        self.save_cmd = [iptables_save]
        self.restore_cmd = [iptables_restore]
        self.ruleset_type = 'iptables'


class Ip6tables(IptablesCommon):
    def __init__(self, ip6tables_save='iptables-save', ip6tables_restore='iptables-restore'):
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
        output = subprocess.check_output([self.ipset, 'list', '-name'], universal_newlines=True)
        return output.splitlines()

    def clear(self):
        LOGGER.debug("Clearing %s rules", self.ruleset_type)
        self._apply(['flush', 'destroy'])


class RestoreScript(object):
    def __init__(self, iptables, ip6tables, ipsets):
        """ Take the ruleset objects as input """
        self.iptables = iptables
        self.ip6tables = ip6tables
        self.ipsets = ipsets

    def write(self, path):
        """ Atomically update the content and permissions of an executable file """
        LOGGER.debug("Writing restore script to '%s'", path)
        tmp = path.with_suffix('.tmp')
        with tmp.open('w') as f:
            for item in self._get_content():
                f.write('%s\n' % item)
        tmp.chmod(0o755)
        tmp.rename(path)

    def _get_content(self):
        content = [
            '#!/bin/sh',
            '',
            'IPSETS="%s"' % self.ipsets.restore_file,
            'IP_FW="%s"' % self.iptables.restore_file,
            'IP6_FW="%s"' % self.ip6tables.restore_file,
            '',
            '[ -f "${IPSETS}" ] && %s < "${IPSETS}"' % ' '.join(self.ipsets.restore_cmd),
            '[ -f "${IP_FW}" ] && %s < "${IP_FW}"' % ' '.join(self.iptables.restore_cmd),
            '[ -f "${IP6_FW}" ] && %s < "${IP6_FW}"' % ' '.join(self.ip6tables.restore_cmd)
        ]
        return content


class ConfigDir(object):
    def __init__(self, dirname):
        self.dirname = dirname
        self.config = self.dirname / 'config.yml'
        self.example_config = Path(__file__).parent / 'etc' / 'config.yml.example'

    def create(self):
        LOGGER.info("Ensuring '%s' exists...", self.dirname)

        try:
            self.dirname.mkdir(parents=True)
        except FileExistsError:
            pass

        if not self.config.is_file():
            LOGGER.info("Config file does not exist. Adding empty example config.\n"
                        "Please edit '%s' before you run fwgen.", self.config)
            copyfile(str(self.example_config), str(self.config))

        LOGGER.info("Setting permissions on '%s'", self.config)
        self.config.chmod(0o600)


class FwGen(object):
    def __init__(self, config):
        defaults = OrderedDict()
        defaults = {
            'restore_files': {
                'iptables': 'fwgen/rules/iptables.restore',
                'ip6tables': 'fwgen/rules/ip6tables.restore',
                'ipsets': 'fwgen/rules/ipsets.restore'
            },
            'cmds': {
                'iptables_save': 'iptables-save',
                'iptables_restore': 'iptables-restore',
                'ip6tables_save': 'ip6tables-save',
                'ip6tables_restore': 'ip6tables-restore',
                'ipset': 'ipset',
                'conntrack': 'conntrack'
            },
            'restore_script': {
                'manage': True,
                'path': 'network/if-pre-up.d/restore-fw'
            }
        }
        self.config = ordered_dict_merge(config, defaults)
        self.iptables = Iptables(self.config['cmds']['iptables_save'],
                                 self.config['cmds']['iptables_restore'])
        self.ip6tables = Ip6tables(self.config['cmds']['ip6tables_save'],
                                   self.config['cmds']['ip6tables_restore'])
        self.ipsets = Ipsets(self.config['cmds']['ipset'])
        self.restore_file = {
            'ip': self._get_path(Path(self.config['restore_files']['iptables'])),
            'ip6': self._get_path(Path(self.config['restore_files']['ip6tables'])),
            'ipset': self._get_path(Path(self.config['restore_files']['ipsets']))
        }
        self.restore_script = self._get_path(Path(self.config['restore_script']['path']))
        self.zone_pattern = re.compile(r'^(.*?)%\{(.+?)\}(.*)$')
        self.variable_pattern = re.compile(r'^(.*?)\$\{(.+?)\}(.*)$')

    @staticmethod
    def _get_path(path):
        if str(path).startswith('/'):
            new_path = path
        else:
            new_path = get_etc() / path
        return new_path

    @staticmethod
    def _get_ipset_tmp_name(ipset):
        return '%s.%s' % (ipset, random_word(3))

    def _output_ipsets(self):
        current_ipsets = self.ipsets.list()

        for ipset, params in self.config.get('ipsets', {}).items():
            # Continue generating temporary setnames until we find one that do not
            # already exist
            tmp = self._get_ipset_tmp_name(ipset)
            while tmp in current_ipsets:
                tmp = self._get_ipset_tmp_name(ipset)

            if ipset in current_ipsets:
                current_ipsets.remove(ipset)
            else:
                create_cmd = ['create %s %s' % (ipset, params['type'])]
                create_cmd.append(params.get('options', None))
                yield ' '.join([i for i in create_cmd if i])

            create_cmd = ['create %s %s' % (tmp, params['type'])]
            create_cmd.append(params.get('options', None))
            yield ' '.join([i for i in create_cmd if i])

            for entry in params['entries']:
                yield self._substitute_variables('add %s %s' % (tmp, entry))

            yield 'swap %s %s' % (tmp, ipset)
            yield 'destroy %s' % tmp

        # Remove any leftover ipsets that we no longer need.
        # List sets causes errors if the referenced ipsets are removed before the
        # list set. To avoid this we need to flush the ipsets before we can destroy
        # them, so we need two passes.
        for ipset in current_ipsets:
            yield 'flush %s' % ipset

        for ipset in current_ipsets:
            yield 'destroy %s' % ipset

    def _get_policy_rules(self):
        for table, chains in DEFAULT_CHAINS.items():
            for chain in chains:
                policy = 'ACCEPT'
                try:
                    policy = self.config['global']['policy'][table][chain]
                except KeyError:
                    pass
                yield (table, ':%s %s' % (chain, policy))

    def _get_zone_rules(self):
        for zone, params in self.config.get('zones', {}).items():
            for table, chains in params.get('rules', {}).items():
                for chain, chain_rules in chains.items():
                    zone_chain = '%s_%s' % (zone, chain)
                    for rule in chain_rules:
                        yield (table, '-A %s %s' % (zone_chain, rule))

    def _get_global_rules(self):
        """ Return the rules from the global ruleset hooks in correct order """
        for ruleset in ['pre_default', 'default', 'pre_zone']:
            rules = {}
            try:
                rules = self.config['global']['rules'][ruleset]
            except KeyError:
                pass

            for rule in self._get_rules(rules):
                yield rule

    def _get_helper_chains(self):
        rules = {}
        try:
            rules = self.config['global']['helper_chains']
        except KeyError:
            pass

        for table, chains in rules.items():
            for chain in chains:
                yield self._get_new_chain_rule(table, chain)

        for rule in self._get_rules(rules):
            yield rule

    @staticmethod
    def _get_rules(rules):
        for table, chains in rules.items():
            for chain, chain_rules in chains.items():
                for rule in chain_rules:
                    yield (table, '-A %s %s' % (chain, rule))

    @staticmethod
    def _get_new_chain_rule(table, chain):
        return (table, ':%s -' % chain)

    def _get_zone_dispatchers(self):
        for zone, params in self.config.get('zones', {}).items():
            for table, chains in params.get('rules', {}).items():
                for chain in chains:
                    dispatcher_chain = '%s_%s' % (zone, chain)
                    yield self._get_new_chain_rule(table, dispatcher_chain)

                    if chain in ['PREROUTING', 'INPUT', 'FORWARD']:
                        yield (table, '-A %s -i %%{%s} -j %s' % (chain, zone, dispatcher_chain))
                    elif chain in ['OUTPUT', 'POSTROUTING']:
                        yield (table, '-A %s -o %%{%s} -j %s' % (chain, zone, dispatcher_chain))
                    else:
                        raise InvalidChain('%s is not a valid built-in chain' % chain)

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

    def _substitute_variables(self, string):
        match = re.search(self.variable_pattern, string)
        if match:
            variable = match.group(2)
            value = self.config['variables'][variable]
            result = '%s%s%s' % (match.group(1), value, match.group(3))
            return self._substitute_variables(result)
        return string

    def _parse_rule(self, rule):
        rule = self._substitute_variables(rule)
        for rule_expanded in self._expand_zones(rule):
            yield rule_expanded

    def _output_rules(self, rules):
        for table in DEFAULT_CHAINS:
            yield '*%s' % table
            for rule_table, rule in rules:
                if rule_table == table:
                    for rule_parsed in self._parse_rule(rule):
                        yield rule_parsed
            yield 'COMMIT'

    def flush_connections(self):
        try:
            cmd = [self.config['cmds']['conntrack'], '-F']
            subprocess.check_call(cmd, stderr=subprocess.DEVNULL)
        except FileNotFoundError as e:
            LOGGER.error('%s. Is conntrack installed?', str(e))
            LOGGER.warning('Continuing without flushing connection tracking table...')
            return

    def save(self):
        self.iptables.save(self.restore_file['ip'])
        self.ip6tables.save(self.restore_file['ip6'])
        self.ipsets.save(self.restore_file['ipset'])

    def apply(self):
        # Apply ipsets first to ensure they exist when the rules are applied
        try:
            self.ipsets.apply(self._output_ipsets())
        except RulesetError as e:
            LOGGER.debug(str(e))
            LOGGER.warning('Could not apply ipsets atomically. Normally this is caused by '
                           'non-compatible changes on ipsets being referenced in the firewall '
                           'ruleset. To resolve this the firewall will be temporary cleared '
                           'before the configuration is reapplied.')
            self.clear()
            self.ipsets.apply(self._output_ipsets())

        rules = []
        rules.extend(self._get_policy_rules())
        rules.extend(self._get_helper_chains())
        rules.extend(self._get_global_rules())
        rules.extend(self._get_zone_dispatchers())
        rules.extend(self._get_zone_rules())

        self.iptables.apply(self._output_rules(rules))
        self.ip6tables.apply(self._output_rules(rules))

    def clear(self):
        # Clear ipsets after the iptables rules to ensure ipsets are not in use
        self.iptables.clear()
        self.ip6tables.clear()
        self.ipsets.clear()

    def write_restore_script(self):
        if not self.config['restore_script']['manage']:
            LOGGER.debug('Restore script management is disabled. Skipping...')
            return

        script = RestoreScript(self.iptables, self.ip6tables, self.ipsets)
        script.write(self.restore_script)


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

    def rollback(self):
        self.clear()

        # Restore ipsets first to ensure they exist if used in firewall rules
        self.ipsets.apply(self.ipsets_rollback)
        self.iptables.apply(self.ip_rollback)
        self.ip6tables.apply(self.ip6_rollback)
