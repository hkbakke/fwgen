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

-  PyYAML
-  ipset

Installation
============

::

    # Python 3.x (recommended)
    apt install ipset python3-yaml python3-pip
    pip3 install fwgen

    # Python 2.x
    apt install ipset python-yaml python-pip
    pip install fwgen

Installing from source
======================

::

    apt install python3-venv
    git clone https://github.com/hkbakke/fwgen
    cd fwgen
    python3 -m venv venv
    . ./venv/bin/activate
    pip install wheel
    python setup.py clean --all bdist_wheel --universal
    deactivate  # Unless you only want to install it in your venv

    apt install ipset python3-yaml python3-pip
    pip3 install dist/<build>.whl

Prepare configuration file
==========================

By default fwgen will give an error if the config file is missing. This is by design to prevent accidental application of the very restrictive default firewall settings, which basically only allows host internal traffic.

To finish up you should do the following (replace python3 with python if python 2 is used):

::

    mkdir /etc/fwgen
    cp $(python3 -c 'import fwgen, os; print(os.path.dirname(fwgen.__file__))')/etc/config.yml.example \
        /etc/fwgen/config.yml
    chown -R root. /etc/fwgen
    chmod 600 /etc/fwgen/*.yml

    # On Debian-based distros you should use restore-fw to ensure the
    # firewall is activated on reboots and ifup
    ln -s $(python3 -c 'import fwgen, os; print(os.path.dirname(fwgen.__file__))')/sbin/restore-fw \
        /etc/network/if-pre-up.d/restore-fw

Update ``/etc/fwgen/config.yml`` with your ruleset. Look at the examples in the config file for guidance.

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

.. _example configuration: fwgen/etc/config.yml.example
