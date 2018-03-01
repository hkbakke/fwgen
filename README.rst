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

It has built-in mechanisms to make remote unattended deployment of linux
firewalls much more robust. If any kind of errors is encountered the ruleset
is automatically rolled back to the previous running one.
To solve the other issue with remote deployment of firewalls, the one where
you deploy a valid ruleset, but you have managed to cut your own access,
fwgen can run user defined checks that can automatically verify that the host
is remotely accessible before storing the new ruleset. If the check command
fails the ruleset will be rolled back.

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

To ensure persistence you must have something that loads the ruleset at boot. An example systemd service is included in `fwgen.service`_. As not all distros use systemd it is not enabled automatically, but a `helper script`_ is available to enable or update the service.

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
    deactivate

    # On your target host
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

fwgen check server setup
========================

If you want to make use of the firewall check commands a script is included, `fwcheck`_, intended to be hosted at the server performing the tests against your firewalls and called via SSH. As you do not want to allow remote firewalls to be able to execute arbitrary commands on the test server you should add some restrictions, and fwcheck helps you enforcing those in a set of standardized checks.

Add a user for fwcheck on the test server

::

    adduser --system --group --shell /bin/bash fwcheck
    
Put fwcheck somewhere logical for ease of use

::

    cp fwcheck /usr/local/bin/
    
Add the ssh public key for the root user (normally found in ``/root/.ssh/id_rsa.pub``) from each of the fwgen firewalls requesting the checks to ``/home/fwcheck/.ssh/authorized_keys`` on the test server. To restrict the key usage to running the fwchecks only, a set of restrictions should be included. Example:

::

    command="fwcheck",no-port-forwarding,no-x11-forwarding,no-agent-forwarding,no-pty ssh-rsa AAAAB3Nza....
   
Example fwgen config on the firewalls:

::

    check_commands:
      # Available tests:
      # 
      #   tcp-test <target-ip> <target-port>
      #       Tests if a TCP port is open on the target
      #
      #   ping-test <target-ip>
      #       Tests if the target is reachable by ping
      #
      #   default-tests <target-ip>
      #       Test if TCP port 22 is open at the target and if it is reachable by ping
      #
      - ssh fwtest@<testhost> default-tests <management-ip-of-this-firewall>
      - <cmd2>
      - <cmd3>

.. _example configuration: https://github.com/hkbakke/fwgen/blob/master/fwgen/doc/examples/config.yml
.. _default configuration: https://github.com/hkbakke/fwgen/blob/master/fwgen/etc/defaults.yml
.. _fwgen.service: https://github.com/hkbakke/fwgen/blob/master/fwgen/doc/examples/fwgen.service
.. _helper script: https://github.com/hkbakke/fwgen/blob/master/scripts/enable-systemd-service
.. _fwcheck: https://github.com/hkbakke/fwgen/blob/master/scripts/fwcheck
