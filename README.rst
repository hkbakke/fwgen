Introduction
============

fwgen is a small framework to simplify the management of
ip(6)tables based firewalls, that also integrates ipset support and
zones in a non-restrictive way. It is *not* an abstraction layer of the
iptables syntax, so you still need to understand how to write iptables
rules and how packets are processed through the iptables chains. This is
the intended project scope to ensure all existing functionality is made
available. fwgen does however help you create an efficient ruleset with
very little effort.

fwgen is mainly targeted towards network gateways and hosts which are
configured via configuration management systems, often with multiple
interfaces and complex rulesets that very fast gets unmanagable or
inefficient if not done right. It may not be worth the effort to install
it if you just have a simple server where you want to allow a couple of
incoming ports.

Advantages of using fwgen:

- Integrates iptables, ip6tables and ipsets in a common management framework
- Uses a simple config file in YAML format for easy and readable configuration
- Separation of duties between the loading of firewall rules at boot/ifup (restore-fw) and the rule generation (fwgen). No complex code are executed during boot/ifup.
- Firewall operations are atomic. It either applies correctly or not, without flushing your existing ruleset, potentially leaving you temporarily exposed. However, ipsets are currently flushed for a very short period to enforce concistency with your configuration.
- Automatic rollback to previous ruleset if not confirmed when applying rulesets in case something goes wrong. This can be disabled if run automatically by configuration management systems etc.
- Namespace support. If executed in a namespace it automatically stores the rulesets in ``/etc/netns/<namespace>/`` instead of in the global namespace.

Requirements
============

- Python 3 (only tested on 3.4 and later, but might work with earlier versions)
- PyYAML
- ipset
- conntrack (only if you want to flush connections)

Installation
============

::

    # Python 3.x
    apt install ipset conntrack python3-yaml python3-pip
    pip3 install fwgen

PyYAML is pulled in as a dependency automatically via pip, but you may get a compiler error if you do not have the correct dependencies installed. It will still work however, just not as fast. I recommend using the distro packaged version if you have it available. In Debian's case that is ``python3-yaml``.

Installing from source
======================

::

    apt install python3-pip python3-venv
    git clone https://github.com/hkbakke/fwgen
    cd fwgen
    python3 -m venv venv
    . ./venv/bin/activate
    pip3 install wheel
    python3 setup.py clean --all bdist_wheel
    deactivate  # Unless you only want to install it in your venv

    # On you target host
    apt install ipset conntrack python3-yaml python3-pip
    pip3 install dist/<build>.whl

Prepare configuration file
==========================

By default fwgen will give an error if the config file is missing. This is by design to prevent accidental application of the very restrictive default firewall settings, which basically only allows host internal traffic.

To create your initial config file you should run:

::

    fwgen --create-config-dir

Update the config with your ruleset. Look at the `example configuration`_ for guidance.

Usage
=====

To generate the new ruleset:

::

    fwgen

To skip confirmation:

::

    fwgen --no-confirm

If ipsets in use causes issues with applying the new ruleset:

::

    fwgen --with-reset

In addition to rules defined in the config file you can add/override rules from command line. Add ``--log-level debug`` to see the resulting complete config.

::

    fwgen --config-json '{"global": {"policy": {"filter": {"INPUT": "ACCEPT"}}}}'

To temporarily clear the running ruleset without overwriting the saved persistent ruleset:

::

    fwgen --no-save --reset

For troubleshooting

::

    fwgen --log-level debug

For other functionality, see:

::

    fwgen --help

.. _example configuration: https://github.com/hkbakke/fwgen/blob/master/fwgen/etc/config.yml.example
