import re
import subprocess
import os
import logging
from collections import OrderedDict

from .helpers import ordered_dict_merge, get_etc


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

class FwGen(object):
    def __init__(self, config):
        self._ip_families = ['ip', 'ip6']

        # Paths that do not start with / are relative to /etc, or /etc/netns/<namespace>
        # if executed within a namespace.
        defaults = OrderedDict()
        defaults = {
            'restore_files': {
                'iptables': 'iptables.restore',
                'ip6tables': 'ip6tables.restore',
                'ipsets': 'ipsets.restore'
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
                'path': '/etc/network/if-pre-up.d/restore-fw'
            }
        }

        self.config = ordered_dict_merge(config, defaults)
        restore_files = self._get_restore_files()
        self._restore_file = {
            'ip': restore_files['iptables'],
            'ip6': restore_files['ip6tables'],
            'ipset': restore_files['ipsets']
        }
        self._restore_cmd = {
            'ip': [self.config['cmds']['iptables_restore']],
            'ip6': [self.config['cmds']['ip6tables_restore']],
            'ipset': [self.config['cmds']['ipset'], 'restore']
        }
        self._save_cmd = {
            'ip': [self.config['cmds']['iptables_save']],
            'ip6': [self.config['cmds']['ip6tables_save']]
        }
        self.zone_pattern = re.compile(r'^(.*?)%\{(.+?)\}(.*)$')
        self.variable_pattern = re.compile(r'^(.*?)\$\{(.+?)\}(.*)$')

    def _get_restore_files(self):
        restore_files = {}
        etc = get_etc()

        for k, v in self.config['restore_files'].items():
            if v.startswith('/'):
                restore_files[k] = v
            else:
                restore_files[k] = '%s/%s' % (etc, v)

        return restore_files

    def _output_ipsets(self, reset=False):
        if reset:
            yield 'flush'
            yield 'destroy'
        else:
            for ipset, params in self.config.get('ipsets', {}).items():
                create_cmd = ['-exist create %s %s' % (ipset, params['type'])]
                create_cmd.append(params.get('options', None))
                yield ' '.join([i for i in create_cmd if i])
                yield 'flush %s' % ipset

                for entry in params['entries']:
                    yield self._substitute_variables('add %s %s' % (ipset, entry))

    def _get_policy_rules(self, reset=False):
        for table, chains in DEFAULT_CHAINS.items():
            for chain in chains:
                policy = 'ACCEPT'

                if not reset:
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
        """
        Returns the rules from the global ruleset hooks in correct order
        """
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

    def _save_ipsets(self, path):
        """
        Avoid using `ipset save` in case there are other
        ipsets used on the system for other purposes. Also
        this avoids storing now unused ipsets from previous
        configurations.
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, 'w') as f:
            for item in self._output_ipsets():
                f.write('%s\n' % item)

    def _save_rules(self, path, family):
        os.makedirs(os.path.dirname(path), exist_ok=True)

        with open(path, 'wb') as f:
            subprocess.check_call(self._save_cmd[family], stdout=f)

    def _apply_rules(self, rules, rule_type):
        data = ('%s\n' % '\n'.join(rules)).encode('utf-8')
        p = subprocess.Popen(
            self._restore_cmd[rule_type],
            stdin=subprocess.PIPE,
            stderr=subprocess.PIPE
            )
        _, stderr = p.communicate(data)

        if p.returncode != 0:
            raise RulesetError(stderr.decode('utf-8'))

    def _restore_rules(self, path, rule_type):
        with open(path, 'rb') as f:
            subprocess.check_call(self._restore_cmd[rule_type], stdin=f)

    def flush_connections(self):
        LOGGER.info('Flushing connection tracking table...')
        try:
            subprocess.check_call(
                [self.config['cmds']['conntrack'], '-F'],
                stderr=subprocess.DEVNULL
            )
        except FileNotFoundError as e:
            LOGGER.error('%s. Is conntrack installed? Continuing without '
                         'flushing connection tracking table...', str(e))
            return

    def save(self):
        for family in self._ip_families:
            self._save_rules(self._restore_file[family], family)

        self._save_ipsets(self._restore_file['ipset'])

    def apply(self, flush_connections=False):
        # Apply ipsets first to ensure they exist when the rules are applied
        self._apply_rules(self._output_ipsets(), 'ipset')

        rules = []
        rules.extend(self._get_policy_rules())
        rules.extend(self._get_helper_chains())
        rules.extend(self._get_global_rules())
        rules.extend(self._get_zone_dispatchers())
        rules.extend(self._get_zone_rules())

        for family in self._ip_families:
            self._apply_rules(self._output_rules(rules), family)

        if flush_connections:
            self.flush_connections()

    def rollback(self):
        for family in self._ip_families:
            if os.path.exists(self._restore_file[family]):
                self._restore_rules(self._restore_file[family], family)
            else:
                self.reset(family)

        if os.path.exists(self._restore_file['ipset']):
            self._restore_rules(self._restore_file['ipset'], 'ipset')
        else:
            self._apply_rules(self._output_ipsets(reset=True), 'ipset')

    def reset(self, family=None):
        families = self._ip_families

        if family:
            families = [family]

        rules = []
        rules.extend(self._get_policy_rules(reset=True))

        for family_ in families:
            self._apply_rules(self._output_rules(rules), family_)

        # Reset ipsets after the rules are removed to ensure ipsets are not in use
        self._apply_rules(self._output_ipsets(reset=True), 'ipset')

    def write_restore_script(self):
        """ Atomically updates the content and permissions of an executable file """
        if self.config['restore_script']['manage']:
            path = self.config['restore_script']['path']
            tmp = '%s.tmp' % path
        else:
            LOGGER.debug('Restore script management is disabled. Skipping...')
            return

        with open(tmp, 'w') as f:
            for item in self._get_restore_script():
                f.write('%s\n' % item)

        os.chmod(tmp, 0o755)
        os.rename(tmp, path)

    def _get_restore_script(self):
        content = [
            '#!/bin/sh',
            '',
            'IPSETS="%s"' % self._restore_file['ipset'],
            'IP_FW="%s"' % self._restore_file['ip'],
            'IP6_FW="%s"' % self._restore_file['ip6'],
            '',
            '[ -f "${IPSETS}" ] && "%s" restore < "${IPSETS}"' % self.config['cmds']['ipset'],
            '[ -f "${IP_FW}" ] && "%s" < "${IP_FW}"' % self.config['cmds']['iptables_restore'],
            '[ -f "${IP6_FW}" ] && "%s" < "${IP6_FW}"' % self.config['cmds']['ip6tables_restore'],
        ]
        return content
