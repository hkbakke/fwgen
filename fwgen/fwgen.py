import re
import subprocess
import os


DEFAULT_CHAINS = {
    'filter': ['INPUT', 'FORWARD', 'OUTPUT'],
    'nat': ['PREROUTING', 'INPUT', 'OUTPUT', 'POSTROUTING'],
    'mangle': ['PREROUTING', 'INPUT', 'FORWARD', 'OUTPUT', 'POSTROUTING'],
    'raw': ['PREROUTING', 'OUTPUT'],
    'security': ['INPUT', 'FORWARD', 'OUTPUT']
}


class InvalidChain(Exception):
    pass

class FwGen(object):
    def __init__(self, config):
        self.config = config
        self._ip_families = ['ip', 'ip6']
        etc = self._get_etc()
        self._restore_file = {
            'ip': b'%s/iptables.restore' % etc,
            'ip6': b'%s/ip6tables.restore' % etc,
            'ipset': b'%s/ipsets.restore' % etc
        }
        self._restore_cmd = {
            'ip': ['iptables-restore'],
            'ip6': ['ip6tables-restore'],
            'ipset': ['ipset', 'restore']
        }
        self._save_cmd = {
            'ip': ['iptables-save'],
            'ip6': ['ip6tables-save']
        }

    def _get_etc(self):
        etc = b'/etc'
        netns = self._get_netns()
        if netns:
            etc = b'/etc/netns/%s' % netns
            os.makedirs(etc, exist_ok=True)

        return etc

    @staticmethod
    def _get_netns():
        output = subprocess.run(['ip', 'netns', 'identify'], stdout=subprocess.PIPE, check=True)
        return output.stdout.strip()

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

            yield from self._get_rules(rules)

    def _get_helper_chains(self):
        rules = {}

        try:
            rules = self.config['global']['helper_chains']
        except KeyError:
            pass

        for table, chains in rules.items():
            for chain in chains:
                yield self._get_new_chain_rule(table, chain)

        yield from self._get_rules(rules)

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
                        raise InvalidChain('%s is not a valid default chain' % chain)

    def _expand_zones(self, rule):
        zone_pattern = re.compile(r'^(.*?)%\{(.+?)\}(.*)$')
        match = re.search(zone_pattern, rule)

        if match:
            zone = match.group(2)

            for interface in self.config['zones'][zone]['interfaces']:
                rule_expanded = '%s%s%s' % (match.group(1), interface, match.group(3))
                yield from self._expand_zones(rule_expanded)
        else:
            yield rule

    def _substitute_variables(self, string):
        variable_pattern = re.compile(r'^(.*?)\$\{(.+?)\}(.*)$')
        match = re.search(variable_pattern, string)

        if match:
            variable = match.group(2)
            value = self.config['variables'][variable]
            result = '%s%s%s' % (match.group(1), value, match.group(3))
            return self._substitute_variables(result)

        return string

    def _parse_rule(self, rule):
        rule = self._substitute_variables(rule)
        yield from self._expand_zones(rule)

    def _output_rules(self, rules):
        for table in DEFAULT_CHAINS:
            yield '*%s' % table

            for rule_table, rule in rules:
                if rule_table == table:
                    yield from self._parse_rule(rule)

            yield 'COMMIT'

    def _save_ipsets(self, path):
        """
        Avoid using `ipset save` in case there are other
        ipsets used on the system for other purposes. Also
        this avoid storing now unused ipsets from previous
        configurations.
        """
        with open(path, 'w') as f:
            for item in self._output_ipsets():
                f.write('%s\n' % item)

    def _save_rules(self, path, family):
        with open(path, 'wb') as f:
            subprocess.run(self._save_cmd[family], stdout=f, check=True)

    def _apply_rules(self, rules, family):
        stdin = ('%s\n' % '\n'.join(rules)).encode('utf-8')
        subprocess.run(self._restore_cmd[family], input=stdin, check=True)

    def _restore_rules(self, path, family):
        with open(path, 'rb') as f:
            subprocess.run(self._restore_cmd[family], stdin=f, check=True)

    def _apply_ipsets(self, ipsets):
        stdin = ('%s\n' % '\n'.join(ipsets)).encode('utf-8')
        subprocess.run(self._restore_cmd['ipset'], input=stdin, check=True)

    def _restore_ipsets(self, path):
        with open(path, 'rb') as f:
            subprocess.run(self._restore_cmd['ipset'], stdin=f, check=True)

    def save(self):
        for family in self._ip_families:
            self._save_rules(self._restore_file[family], family)

        self._save_ipsets(self._restore_file['ipset'])

    def apply(self):
        # Apply ipsets first to ensure they exist when the rules are applied
        self._apply_ipsets(self._output_ipsets())

        rules = []
        rules.extend(self._get_policy_rules())
        rules.extend(self._get_helper_chains())
        rules.extend(self._get_global_rules())
        rules.extend(self._get_zone_dispatchers())
        rules.extend(self._get_zone_rules())

        for family in self._ip_families:
            self._apply_rules(self._output_rules(rules), family)

    def commit(self):
        self.apply()
        self.save()

    def rollback(self):
        for family in self._ip_families:
            if os.path.exists(self._restore_file[family]):
                self._restore_rules(self._restore_file[family], family)
            else:
                self.reset(family)

        if os.path.exists(self._restore_file['ipset']):
            self._restore_ipsets(self._restore_file['ipset'])
        else:
            self._apply_ipsets(self._output_ipsets(reset=True))

    def reset(self, family=None):
        families = self._ip_families

        if family:
            families = [family]

        rules = []
        rules.extend(self._get_policy_rules(reset=True))

        for family_ in families:
            self._apply_rules(self._output_rules(rules), family_)

        # Reset ipsets after the rules are removed to ensure ipsets are not in use
        self._apply_ipsets(self._output_ipsets(reset=True))
