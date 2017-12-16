import pytest
from collections import OrderedDict

from fwgen import fwgen


class OrderedDefaultDict(OrderedDict):
    """
    Helper class for ordered default dicts
    """
    def __missing__(self, key):
        val = self[key] = OrderedDefaultDict()
        return val

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
            'policy': {
                'filter': {
                    'INPUT': 'DROP',
                    'OUTPUT': 'DROP'
                },
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

    def test_get_rules(rules):
        rules = OrderedDefaultDict()
        rules['filter']['INPUT'] = [
            '-p tcp --dport 22 -j ACCEPT',
            '-p icmp --icmp-type echo-request -j ACCEPT',
            '-j CUSTOM_REJECT'
        ]
        rules['filter']['OUTPUT'] = [
            '-j ACCEPT'
        ]
        rules['nat']['POSTROUTING'] = [
            '-j MASQUERADE'
        ]
        fw = fwgen.FwGen({})
        rule_list = [
            ('filter', '-A INPUT -p tcp --dport 22 -j ACCEPT'),
            ('filter', '-A INPUT -p icmp --icmp-type echo-request -j ACCEPT'),
            ('filter', '-A INPUT -j CUSTOM_REJECT'),
            ('filter', '-A OUTPUT -j ACCEPT'),
            ('nat', '-A POSTROUTING -j MASQUERADE')
        ]
        assert [i for i in fw._get_rules(rules)] == rule_list

    def test_get_zone_rules(self):
        config = OrderedDefaultDict()
        config['zones']['LAN']['rules']['filter']['INPUT'] = [
            '-p tcp --dport 22 -j ACCEPT',
            '-p icmp --icmp-type echo-request -j ACCEPT',
            '-j CUSTOM_REJECT'
        ]
        config['zones']['LAN']['rules']['filter']['OUTPUT'] = [
            '-j ACCEPT'
        ]
        config['zones']['LAN']['rules']['nat']['POSTROUTING'] = [
            '-j MASQUERADE'
        ]
        fw = fwgen.FwGen(config)
        rule_list = [
            ('filter', '-A ZONE0_INPUT -p tcp --dport 22 -j ACCEPT'),
            ('filter', '-A ZONE0_INPUT -p icmp --icmp-type echo-request -j ACCEPT'),
            ('filter', '-A ZONE0_INPUT -j CUSTOM_REJECT'),
            ('filter', '-A ZONE0_OUTPUT -j ACCEPT'),
            ('nat', '-A ZONE0_POSTROUTING -j MASQUERADE')
        ]
        assert [i for i in fw._get_zone_rules()] == rule_list

    def test_get_helper_chains(self):
        config = OrderedDefaultDict()
        config['helper_chains']['filter']['CUSTOM_REJECT'] = [
            '-p tcp -j REJECT --reject-with tcp-reset',
            '-j REJECT'
        ]
        config['helper_chains']['filter']['LOG_DROP'] = [
            '-j LOG --log-level warning --log-prefix "IPTABLES_DROP: "',
            '-j DROP'
        ]
        fw = fwgen.FwGen(config)
        rule_list = [
            ('filter', ':CUSTOM_REJECT -'),
            ('filter', ':LOG_DROP -'),
            ('filter', '-A CUSTOM_REJECT -p tcp -j REJECT --reject-with tcp-reset'),
            ('filter', '-A CUSTOM_REJECT -j REJECT'),
            ('filter', '-A LOG_DROP -j LOG --log-level warning --log-prefix "IPTABLES_DROP: "'),
            ('filter', '-A LOG_DROP -j DROP'),
        ]
        assert [i for i in fw._get_helper_chains()] == rule_list

    def test_get_new_chain_rule(self):
        fw = fwgen.FwGen({})
        assert fw._get_new_chain_rule('filter', 'LOG_REJECT') == ('filter', ':LOG_REJECT -')
