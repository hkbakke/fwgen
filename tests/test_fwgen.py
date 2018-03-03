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
            '-A FORWARD -i eth1 -o eth3 -j ACCEPT'
        ]

        result = list(fw._expand_zones(rule))
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

        result = list(fw._expand_zones(rule))
        assert result == rules_expanded

    def test_object_expansion_v4(self):
        config = {
            'objects': {
                'host_v4': '10.0.0.10',
                'host2_v4': '192.168.0.10'
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-A PREROUTING -s ${host_v4} -j DNAT --to-destination ${host2_v4}'
        rules_expanded = ['-4 -A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10']

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_object_expansion_v4_as_v4(self):
        config = {
            'objects': {
                'host_v4': '10.0.0.10',
                'host2_v4': '192.168.0.10'
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-4 -A PREROUTING -s ${host_v4} -j DNAT --to-destination ${host2_v4}'
        rules_expanded = ['-4 -A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10']

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_object_expansion_v4_only(self):
        config = {
            'objects': {
                'host': [
                    '10.0.0.10',
                    'fd33::10'
                ]
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-4 -A INPUT -s ${host} -j ACCEPT'
        rules_expanded = ['-4 -A INPUT -s 10.0.0.10 -j ACCEPT']

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_object_expansion_v6(self):
        config = {
            'objects': {
                'host_v6': 'fd32::1',
                'net_v6': 'fd33::/64'
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-A INPUT -s ${host_v6} -d ${net_v6} -j ACCEPT'
        rules_expanded = ['-6 -A INPUT -s fd32::1 -d fd33::/64 -j ACCEPT']

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_object_expansion_v6_as_v6(self):
        config = {
            'objects': {
                'host_v6': 'fd32::1',
                'net_v6': 'fd33::/64'
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-6 -A INPUT -s ${host_v6} -d ${net_v6} -j ACCEPT'
        rules_expanded = ['-6 -A INPUT -s fd32::1 -d fd33::/64 -j ACCEPT']

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_object_expansion_v6_only(self):
        config = {
            'objects': {
                'host': [
                    '10.0.0.10',
                    'fd33::10'
                ]
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-6 -A INPUT -s ${host} -j ACCEPT'
        rules_expanded = ['-6 -A INPUT -s fd33::10 -j ACCEPT']

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_list_object_expansion(self):
        config = {
            'objects': {
                'hosts1': [
                    '10.0.0.1',
                    'fd32::1',
                    '10.0.0.3'
                ],
                'hosts2': [
                    'fd44::1',
                    '192.168.0.1',
                    '192.168.0.2',
                ]
            }
        }
        fw = fwgen.FwGen(config)
        rule = '-A FORWARD -s ${hosts1} -d ${hosts2} -j ACCEPT'
        rules_expanded = [
            '-4 -A FORWARD -s 10.0.0.1 -d 192.168.0.1 -j ACCEPT',
            '-4 -A FORWARD -s 10.0.0.1 -d 192.168.0.2 -j ACCEPT',
            '-6 -A FORWARD -s fd32::1 -d fd44::1 -j ACCEPT',
            '-4 -A FORWARD -s 10.0.0.3 -d 192.168.0.1 -j ACCEPT',
            '-4 -A FORWARD -s 10.0.0.3 -d 192.168.0.2 -j ACCEPT',
            ]

        result = list(fw._expand_objects(rule))
        assert result == rules_expanded

    def test_no_object_expansion(self):
        config = {}
        fw = fwgen.FwGen(config)
        rule = '-A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10'
        rule_expanded = ['-A PREROUTING -s 10.0.0.10 -j DNAT --to-destination 192.168.0.10']

        result = list(fw._expand_objects(rule))
        assert result == rule_expanded

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
        assert sorted(fw._get_policy_rules()) == sorted(policy_rules)

    def test_get_rules(self):
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
        assert list(fw._get_rules(rules)) == rule_list

    def test_get_zone_rules(self):
        config = OrderedDefaultDict()
        config['zones']['lan']['rules']['filter']['INPUT'] = [
            '-p tcp --dport 22 -j ACCEPT',
            '-p icmp --icmp-type echo-request -j ACCEPT',
            '-j CUSTOM_REJECT'
        ]
        config['zones']['lan']['rules']['filter']['FORWARD'] = [
            '-j ACCEPT'
        ]
        config['zones']['lan']['rules']['filter']['OUTPUT'] = [
            '-j ACCEPT'
        ]
        config['zones']['lan']['rules']['mangle']['PREROUTING'] = [
            '-j DSCP --set-dscp 18'
        ]
        config['zones']['lan']['rules']['nat']['POSTROUTING'] = [
            '-j MASQUERADE'
        ]
        fw = fwgen.FwGen(config)
        rule_list = [
            ('filter', ':zone0_INPUT -'),
            ('filter', '-A INPUT -i %{lan} -j zone0_INPUT'),
            ('filter', '-A zone0_INPUT -p tcp --dport 22 -j ACCEPT'),
            ('filter', '-A zone0_INPUT -p icmp --icmp-type echo-request -j ACCEPT'),
            ('filter', '-A zone0_INPUT -j CUSTOM_REJECT'),
            ('filter', ':zone0_FORWARD -'),
            ('filter', '-A FORWARD -i %{lan} -j zone0_FORWARD'),
            ('filter', '-A zone0_FORWARD -o %{lan} -m comment --comment "Intra-zone" -j ACCEPT'),
            ('filter', '-A zone0_FORWARD -j ACCEPT'),
            ('filter', ':zone0_OUTPUT -'),
            ('filter', '-A OUTPUT -o %{lan} -j zone0_OUTPUT'),
            ('filter', '-A zone0_OUTPUT -j ACCEPT'),
            ('mangle', ':zone0_PREROUTING -'),
            ('mangle', '-A PREROUTING -i %{lan} -j zone0_PREROUTING'),
            ('mangle', '-A zone0_PREROUTING -j DSCP --set-dscp 18'),
            ('nat', ':zone0_POSTROUTING -'),
            ('nat', '-A POSTROUTING -o %{lan} -j zone0_POSTROUTING'),
            ('nat', '-A zone0_POSTROUTING -j MASQUERADE')
        ]
        assert list(fw._get_zone_rules()) == rule_list

    def test_zone_to_zone_rules(self):
        config = OrderedDefaultDict()
        config['zones']['lan']['rules']['filter']['to']['local'] = [
            '-p tcp --dport 22 -j ACCEPT',
            '-p icmp --icmp-type echo-request -j ACCEPT',
            '-j CUSTOM_REJECT'
        ]
        config['zones']['lan']['rules']['filter']['to']['wan'] = [
            '-j ACCEPT',
        ]
        config['zones']['lan']['rules']['filter']['to']['default'] = [
            '-j LOG_REJECT',
        ]
        config['zones']['wan']['rules']['filter']['to']['lan'] = [
            '-j -p tcp --dport 443',
            '-j DROP'
        ]
        config['zones']['local']['rules']['filter']['to']['wan'] = [
            '-j LOG_ACCEPT',
        ]
        config['zones']['local']['rules']['filter']['to']['default'] = [
            '-j ACCEPT',
        ]
        fw = fwgen.FwGen(config)
        rule_list = [
            ('filter', ':zone0_INPUT -'),
            ('filter', '-A INPUT -i %{lan} -j zone0_INPUT'),
            ('filter', ':zone0_FORWARD -'),
            ('filter', '-A FORWARD -i %{lan} -j zone0_FORWARD'),
            ('filter', '-A zone0_FORWARD -o %{lan} -m comment --comment "Intra-zone" -j ACCEPT'),
            ('filter', ':zone0_to_local -'),
            ('filter', '-A zone0_INPUT -m comment --comment "lan -> local" -j zone0_to_local'),
            ('filter', '-A zone0_to_local -p tcp --dport 22 -j ACCEPT'),
            ('filter', '-A zone0_to_local -p icmp --icmp-type echo-request -j ACCEPT'),
            ('filter', '-A zone0_to_local -j CUSTOM_REJECT'),
            ('filter', ':zone0_to_zone1 -'),
            ('filter', '-A zone0_FORWARD -o %{wan} -m comment --comment "lan -> wan" -j zone0_to_zone1'),
            ('filter', '-A zone0_to_zone1 -j ACCEPT'),
            ('filter', ':zone0_default -'),
            ('filter', '-A zone0_FORWARD -j zone0_default'),
            ('filter', '-A zone0_INPUT -j zone0_default'),
            ('filter', '-A zone0_default -j LOG_REJECT'),
            ('filter', ':zone1_INPUT -'),
            ('filter', '-A INPUT -i %{wan} -j zone1_INPUT'),
            ('filter', ':zone1_FORWARD -'),
            ('filter', '-A FORWARD -i %{wan} -j zone1_FORWARD'),
            ('filter', '-A zone1_FORWARD -o %{wan} -m comment --comment "Intra-zone" -j ACCEPT'),
            ('filter', ':zone1_to_zone0 -'),
            ('filter', '-A zone1_FORWARD -o %{lan} -m comment --comment "wan -> lan" -j zone1_to_zone0'),
            ('filter', '-A zone1_to_zone0 -j -p tcp --dport 443'),
            ('filter', '-A zone1_to_zone0 -j DROP'),
            ('filter', ':local_to_zone1 -'),
            ('filter', '-A OUTPUT -o %{wan} -m comment --comment "local -> wan" -j local_to_zone1'),
            ('filter', '-A local_to_zone1 -j LOG_ACCEPT'),
            ('filter', ':local_default -'),
            ('filter', '-A OUTPUT -j local_default'),
            ('filter', '-A local_default -j ACCEPT'),
        ]
        assert list(fw._get_zone_rules()) == rule_list

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
        assert list(fw._get_helper_chains()) == rule_list

    def test_new_chain(self):
        assert fwgen.FwGen._new_chain('LOG_REJECT') == ':LOG_REJECT -'

    def test_ipset_diff_filter(self):
        diff = [
            'create dmz_collectd_hosts hash:ip family inet hashsize 1024 maxelem 65536',
            'add dmz_collectd_hosts 10.0.5.19',
            'add dmz_collectd_hosts 10.0.5.10',
            'create no_proxy_v4 hash:net family inet hashsize 1024 maxelem 65536',
            'add no_proxy_v4 10.0.0.1',
            'add no_proxy_v4 10.0.6.14'
        ]
        output = [
            'create dmz_collectd_hosts hash:ip family inet hashsize 1024 maxelem 65536',
            'add dmz_collectd_hosts 10.0.5.10',
            'add dmz_collectd_hosts 10.0.5.19',
            'create no_proxy_v4 hash:net family inet hashsize 1024 maxelem 65536',
            'add no_proxy_v4 10.0.0.1',
            'add no_proxy_v4 10.0.6.14'
        ]
        assert list(fwgen.Ipsets._diff_filter(diff)) == output

    def test_create_zone_forward(self):
        config = {
            'zones': {
                'lan': {
                    'interfaces': ['eth0', 'eth1']
                }
            }
        }
        output = [
            ':zone0_FORWARD -',
            '-A FORWARD -i %{lan} -j zone0_FORWARD',
            '-A zone0_FORWARD -o %{lan} -m comment --comment "Intra-zone" -j ACCEPT'
        ]
        fw = fwgen.FwGen(config)
        zone = 'lan'
        target = 'zone0_FORWARD'
        assert list(fw._create_zone_forward(zone, target)) == output

    def test_create_zone_forward_block_intra(self):
        config = {
            'zones': {
                'lan': {
                    'interfaces': ['eth0', 'eth1'],
                }
            }
        }
        output = [
            ':zone0_FORWARD -',
            '-A FORWARD -i %{lan} -j zone0_FORWARD',
        ]
        fw = fwgen.FwGen(config)
        zone = 'lan'
        target = 'zone0_FORWARD'
        assert list(fw._create_zone_forward(zone, target, False)) == output

    def test_get_zone_id(self):
        config = OrderedDefaultDict()
        config['zones']['lan'] = {}
        config['zones']['wan'] = {}
        config['zones']['dmz'] = {}
        fw = fwgen.FwGen(config)
        assert fw._get_zone_id('lan') == 0
        assert fw._get_zone_id('wan') == 1
        assert fw._get_zone_id('dmz') == 2

    def test_get_zone_name(self):
        config = {
            'zones': {
                'lan': {},
            }
        }
        fw = fwgen.FwGen(config)
        assert fw._get_zone_name('lan') == 'zone0'
        assert fw._get_zone_name('local') == 'local'
        assert fw._get_zone_name('default') == 'default'

    def test_create_zone_forward(self):
        fw = fwgen.FwGen(config={})
        output = [
            ':lan_FORWARD -',
            '-A FORWARD -i %{lan} -j lan_FORWARD',
            '-A lan_FORWARD -o %{lan} -m comment --comment "Intra-zone" -j ACCEPT'
        ]
        assert list(fw._create_zone_forward('lan', 'lan_FORWARD')) == output

    def test_create_zone_forward_no_intra_zone(self):
        fw = fwgen.FwGen(config={})
        output = [
            ':lan_FORWARD -',
            '-A FORWARD -i %{lan} -j lan_FORWARD',
        ]
        assert list(fw._create_zone_forward('lan', 'lan_FORWARD', False)) == output
