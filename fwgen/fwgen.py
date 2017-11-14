import re
import subprocess
import logging
import shutil
import filecmp
from collections import OrderedDict
from pathlib import Path

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
        self._restore(path)

    def _restore(self, path):
        with path.open('rb') as f:
            subprocess.check_call(self.restore_cmd, stdin=f)

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
    def apply(self, rules):
        LOGGER.debug("Applying %s rules", self.ruleset_type)
        self._apply(rules)

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


class FirewallService(object):
    def __init__(self, name, iptables, ip6tables, ipsets):
        """ Take the ruleset objects as input """
        self.iptables = iptables
        self.ip6tables = ip6tables
        self.ipsets = ipsets
        self.name = name
        self.unitfile = Path('/etc/systemd/system') / Path('%s.service' % name)

    def create(self):
        tmp = self.unitfile.with_suffix('.tmp')
        with tmp.open('w') as f:
            for item in self._get_content():
                f.write('%s\n' % item)

        if self.unitfile.exists() and filecmp.cmp(str(self.unitfile), str(tmp)):
            LOGGER.debug("'%s' do not need updating", self.unitfile)
            tmp.unlink()
            return

        tmp.chmod(0o644)
        LOGGER.debug("Updating '%s'", self.unitfile)
        tmp.rename(self.unitfile)
        self.reload()

    def _enable(self):
        cmd = ['systemctl', 'enable', self.unitfile.name]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                             universal_newlines=True).strip()
        except subprocess.CalledProcessError as e:
            LOGGER.error(e.output)
            raise
        if output:
            LOGGER.debug(output)

    def enable(self):
        self.create()
        LOGGER.debug("Enabling service '%s'", self.name)
        self._enable()

    def _disable(self):
        cmd = ['systemctl', 'disable', self.unitfile.name]
        try:
            output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                             universal_newlines=True).strip()
        except subprocess.CalledProcessError as e:
            LOGGER.error(e.output)
            raise
        if output:
            LOGGER.debug(output)

    def disable(self):
        if self.unitfile.exists():
            LOGGER.debug("Disabling service '%s'", self.name)
            self.stop()
            self._disable()
            self.unitfile.unlink()
            self.reload()
        else:
            LOGGER.debug("Service '%s' is disabled", self.name)

    def start(self):
        LOGGER.debug("Starting service '%s'", self.name)
        subprocess.check_call(['systemctl', 'start', self.unitfile.name])

    def stop(self):
        LOGGER.debug("Stopping service '%s'", self.name)
        subprocess.check_call(['systemctl', 'stop', self.unitfile.name])

    @staticmethod
    def reload():
        LOGGER.debug('Reloading systemd service configuration')
        subprocess.check_call(['systemctl', 'daemon-reload'])

    def _get_content(self):
        content = [
            '[Unit]',
            'Description=fwgen firewall',
            '',
            '[Service]',
            'Type=oneshot',
            'RemainAfterExit=yes',
            'ExecStart=%s -file "%s"' % (
                ' '.join(self.ipsets.restore_cmd), self.ipsets.restore_file),
            'ExecStart=%s "%s"' % (
                ' '.join(self.iptables.restore_cmd), self.iptables.restore_file),
            'ExecStart=%s "%s"' % (
                ' '.join(self.ip6tables.restore_cmd), self.ip6tables.restore_file),
            'ExecReload=/usr/local/bin/fwgen --restore --no-confirm',
            'ExecStop=/usr/local/bin/fwgen --clear --no-save --no-confirm',
            '',
            '[Install]',
            'WantedBy=multi-user.target'
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
            shutil.copyfile(str(self.example_config), str(self.config))

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
                'iptables_save': shutil.which('iptables-save'),
                'iptables_restore': shutil.which('iptables-restore'),
                'ip6tables_save': shutil.which('ip6tables-save'),
                'ip6tables_restore': shutil.which('ip6tables-restore'),
                'ipset': shutil.which('ipset'),
                'conntrack': 'conntrack'
            },
            'systemd_service': {
                'enable': True,
                'name': 'fwgen'
            },
            'check_commands': []
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
        self.zone_pattern = re.compile(r'^(.*?)%\{(.+?)\}(.*)$')
        self.variable_pattern = re.compile(r'^(.*?)\$\{(.+?)\}(.*)$')

    @staticmethod
    def _get_path(path):
        if str(path).startswith('/'):
            new_path = path
        else:
            new_path = get_etc() / path
        return new_path

    def _output_ipsets(self):
        output = []
        for ipset, params in self.config.get('ipsets', {}).items():
            create_cmd = ['create %s %s' % (ipset, params['type'])]
            create_cmd.append(params.get('options', None))
            output.append(' '.join([i for i in create_cmd if i]))
            for entry in params['entries']:
                output.append(self._substitute_variables('add %s %s' % (ipset, entry)))
        return output

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
        output = []
        for table in DEFAULT_CHAINS:
            output.append('*%s' % table)
            for rule_table, rule in rules:
                if rule_table == table:
                    for rule_parsed in self._parse_rule(rule):
                        output.append(rule_parsed)
            output.append('COMMIT')
        return output

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

    def restore(self):
        self.iptables.restore(self.restore_file['ip'])
        self.ip6tables.restore(self.restore_file['ip6'])
        self.ipsets.restore(self.restore_file['ipset'])

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
        rules.extend(self._get_global_rules())
        rules.extend(self._get_zone_dispatchers())
        rules.extend(self._get_zone_rules())
        iptables_rules = self._output_rules(rules)
        self._apply(iptables_rules, iptables_rules, self._output_ipsets())

    def clear(self):
        # Clear ipsets after the iptables rules to ensure ipsets are not in use
        self.iptables.clear()
        self.ip6tables.clear()
        self.ipsets.clear()

    def service(self):
        service = FirewallService(self.config['systemd_service']['name'], self.iptables,
                                  self.ip6tables, self.ipsets)
        if self.config['systemd_service']['enable']:
            service.enable()
            service.start()
        else:
            service.disable()


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
            LOGGER.debug('Command: %s', cmd)
            try:
                output = subprocess.check_output(cmd.split(), stderr=subprocess.STDOUT,
                                                 universal_newlines=True).strip()
            except subprocess.CalledProcessError as e:
                LOGGER.error(e.output)
                raise
            if output:
                LOGGER.debug(output)

    def rollback(self):
        self._apply(self.ip_rollback, self.ip6_rollback, self.ipsets_rollback)
