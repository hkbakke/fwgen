import pytest

import fwgen

class TestFwGen(object):
    def test_zone_expansion(self):
        config = {
            'zones': {
                'lan': {
                    'interfaces': ['eth0', 'eth1']
                },
                'dmz': {
                    'interfaces': ['eth2', 'eth3']
                }
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-A FORWARD -i %{lan} -o %{dmz} -j ACCEPT'
        rules_expanded = [
            '-A FORWARD -i eth0 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth0 -o eth3 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth2 -j ACCEPT',
            '-A FORWARD -i eth1 -o eth3 -j ACCEPT',
        ]

        result = [i for i in fw._expand_zones(rule)]
        assert result == rules_expanded

    def test_zone_expansion_no_zone(self):
        config = {
            'zones': {
                'lan': {
                    'interfaces': ['eth0', 'eth1']
                },
                'dmz': {
                    'interfaces': ['eth2', 'eth3']
                }
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-A INPUT -i lo -j ACCEPT'
        rules_expanded = [rule]

        result = [i for i in fw._expand_zones(rule)]
        assert result == rules_expanded

    def test_variable_substitution(self):
        config = {
            'variables': {
                'host1': '10.0.0.10',
                'host2': '192.168.0.10'
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-A PREROUTING -s ${host1} -j DNAT --to-destination ${host2}'
        rule_substituted = '-A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10'

        result = fw._substitute_variables(rule)
        assert result == rule_substituted

    def test_no_variable_substitution(self):
        config = {}
        fw = fwgen.FwGen(config)
        rule = '-A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10'
        rule_substituted = '-A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10'

        result = fw._substitute_variables(rule)
        assert result == rule_substituted

    def test_get_policy_rules(self):
        config = {
            'global': {
                'policy': {
                    'filter': {
                        'INPUT': 'DROP',
                        'OUTPUT': 'DROP'
                    },
                }
            }
        }
        fw = fwgen.FwGen(config)
        policy_rules = [
            ('filter', ':INPUT DROP'),
            ('filter', ':FORWARD ACCEPT'),
            ('filter', ':OUTPUT DROP'),
            ('nat', ':PREROUTING ACCEPT'),
            ('nat', ':INPUT ACCEPT'),
            ('nat', ':OUTPUT ACCEPT'),
            ('nat', ':POSTROUTING ACCEPT'),
            ('security', ':INPUT ACCEPT'),
            ('security', ':FORWARD ACCEPT'),
            ('security', ':OUTPUT ACCEPT'),
            ('mangle', ':PREROUTING ACCEPT'),
            ('mangle', ':INPUT ACCEPT'),
            ('mangle', ':FORWARD ACCEPT'),
            ('mangle', ':OUTPUT ACCEPT'),
            ('mangle', ':POSTROUTING ACCEPT'),
            ('raw', ':PREROUTING ACCEPT'),
            ('raw', ':OUTPUT ACCEPT'),
        ]
        assert sorted([i for i in fw._get_policy_rules()]) == sorted(policy_rules)

    def test_get_policy_rules_reset(self):
        config = {
            'global': {
                'policy': {
                    'filter': {
                        'INPUT': 'DROP',
                        'OUTPUT': 'DROP'
                    },
                }
            }
        }
        fw = fwgen.FwGen(config)
        policy_rules = [
            ('filter', ':INPUT ACCEPT'),
            ('filter', ':FORWARD ACCEPT'),
            ('filter', ':OUTPUT ACCEPT'),
            ('nat', ':PREROUTING ACCEPT'),
            ('nat', ':INPUT ACCEPT'),
            ('nat', ':OUTPUT ACCEPT'),
            ('nat', ':POSTROUTING ACCEPT'),
            ('security', ':INPUT ACCEPT'),
            ('security', ':FORWARD ACCEPT'),
            ('security', ':OUTPUT ACCEPT'),
            ('mangle', ':PREROUTING ACCEPT'),
            ('mangle', ':INPUT ACCEPT'),
            ('mangle', ':FORWARD ACCEPT'),
            ('mangle', ':OUTPUT ACCEPT'),
            ('mangle', ':POSTROUTING ACCEPT'),
            ('raw', ':PREROUTING ACCEPT'),
            ('raw', ':OUTPUT ACCEPT'),
        ]
        assert sorted([i for i in fw._get_policy_rules(reset=True)]) == sorted(policy_rules)
