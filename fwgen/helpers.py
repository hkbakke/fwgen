import os
import subprocess
import logging
from shutil import copyfile
from collections import OrderedDict
from pkg_resources import resource_filename
from pathlib import Path


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
    etc = Path('/etc')
    netns = get_netns()

    if netns:
        etc = Path('/etc/netns') / netns

    return etc

def get_netns():
    cmd = ['ip', 'netns', 'identify', str(os.getpid())]
    return subprocess.check_output(cmd).strip().decode('utf-8')

def create_config_dir(path):
    if path is None:
        path = Path(get_etc()) / 'fwgen'

    LOGGER.info("Ensuring '%s' exists...", path)

    try:
        path.mkdir(parents=True)
    except FileExistsError:
        pass
    example_config = Path(resource_filename('fwgen', 'etc/config.yml.example'))
    config = path / 'config.yml'

    if not config.is_file():
        LOGGER.info("Config file does not exist. Adding empty example config.\n"
                    "Please edit '%s' before you run fwgen. The default policy is to drop all new "
                    "sessions!", config)
        copyfile(str(example_config), str(config))

    LOGGER.info("Setting permissions on '%s'", config)
    config.chmod(0o600)
