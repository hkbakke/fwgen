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
- Separation of duties between the loading of firewall rules at boot (restore files) and the rule generation (fwgen). No complex code are executed during boot/ifup.
- Firewall operations are atomic. It either applies correctly or not, without flushing your existing ruleset, potentially leaving you temporarily exposed.
- Automatic rollback to previous ruleset if something goes wrong
- Supports check commands to automatically roll back ruleset if check fails
- Combines IPv4 and IPv6 in a single non-duplicated config
- Automatically archives rulesets which later can be easily diffed or restored

Requirements
============

- Python 3 (only tested on 3.4 and later, but might work with earlier versions)
- PyYAML
- ipset

Installation
============

::

    # Debian / Ubuntu
    apt install ipset python3-yaml python3-pip -y
    pip3 install fwgen --upgrade

::

    # CentOS 7
    rpm -ivh https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm
    yum install -y python34-pip
    pip3 install fwgen --upgrade

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
    apt install ipset python3-yaml python3-pip
    pip3 install dist/<build>.whl --upgrade

Prepare configuration file
==========================

By default fwgen will give an error if the config file is missing. This is by design to prevent accidental application of the very restrictive default firewall settings, which basically only allows host internal traffic.

To create your initial config file you should run:

::

    fwgen --create-config-dir

Update the config with your ruleset. It is by default located in ``/etc/fwgen/config.yml``. Look at the `example configuration`_ for guidance. fwgen also has some built-in helper chains and defaults available for ease of use. See the `default configuration`_ for those.

Usage
=====

To generate the new ruleset:

::

    fwgen apply

To skip confirmation:

::

    fwgen apply --no-confirm

In addition to rules defined in the config file you can add/override rules from command line. Add ``--log-level debug`` to see the resulting complete config.

::

    fwgen --config-json '{"policy": {"filter": {"INPUT": "ACCEPT"}}}' apply

To temporarily clear the running ruleset without overwriting the saved persistent ruleset:

::

    fwgen apply --no-save --clear

To list archived rulesets:

::

    fwgen show archive

To view changes between currently running and archived ruleset:

::

    fwgen show archive <index|name>

You can restore your saved or archived rulesets:

::

    # Restores your currently saved ruleset
    fwgen apply --restore

    # Restores a ruleset from the archive
    fwgen apply --archive <index|name>


To view the currently running configuration:

::

    fwgen show running

For troubleshooting:

::

    fwgen --log-level debug apply

For a complete list of the functionality, see:

::

    fwgen --help

.. _example configuration: https://github.com/hkbakke/fwgen/blob/master/fwgen/etc/config.yml.example
.. _default configuration: https://github.com/hkbakke/fwgen/blob/master/fwgen/etc/defaults.yml
