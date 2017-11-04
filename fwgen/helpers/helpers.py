import os
import subprocess
import logging
from shutil import copyfile
from collections import OrderedDict
from pkg_resources import resource_filename


LOGGER = logging.getLogger(__name__)


def ordered_dict_merge(d1, d2):
    """
    Deep merge d1 into d2
    """
    for k, v in d1.items():
        if isinstance(v, OrderedDict):
            node = d2.setdefault(k, OrderedDict())
            ordered_dict_merge(v, node)
        else:
            d2[k] = v

    return d2

def get_etc():
    etc = '/etc'
    netns = get_netns()

    if netns:
        etc = '/etc/netns/%s' % netns

    return etc

def get_netns():
    cmd = ['ip', 'netns', 'identify', str(os.getpid())]
    return subprocess.check_output(cmd).strip().decode('utf-8')

def create_config_dir(path):
    if path is None:
        path = os.path.join(get_etc(), 'fwgen')

    LOGGER.info("Ensuring '%s' exists...", path)

    os.makedirs(path, exist_ok=True)
    example_config = resource_filename('fwgen', 'etc/config.yml.example')
    config = os.path.join(path, 'config.yml')

    if not os.path.isfile(config):
        LOGGER.info("Config file does not exist. Adding empty example config.\n"
                    "Please edit '%s' before you run fwgen. The default policy is to drop all new "
                    "sessions!", config)
        copyfile(example_config, config)

    LOGGER.info("Setting permissions on '%s'", config)
    os.chmod(config, 0o600)
