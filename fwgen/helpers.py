import os
import subprocess
import logging
from collections import OrderedDict
from pathlib import Path
import string
import random

import yaml


LOGGER = logging.getLogger(__name__)


def ordered_dict_merge(d1, d2):
    """ Deep merge d1 into d2 """
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

def random_word(length=3):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(length))

def yaml_load_ordered(stream, Loader=yaml.Loader, object_pairs_hook=OrderedDict):
    class OrderedLoader(Loader):
        pass

    def construct_mapping(loader, node):
        loader.flatten_mapping(node)
        return object_pairs_hook(loader.construct_pairs(node))

    OrderedLoader.add_constructor(
        yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
        construct_mapping)

    return yaml.load(stream, OrderedLoader)

def run_command(cmd):
    LOGGER.debug('Running command: %s', ' '.join(cmd))
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT,
                                         universal_newlines=True)
    except subprocess.CalledProcessError as e:
        if e.output:
            LOGGER.error(e.output.rstrip('\n'))
        raise

    if output:
        LOGGER.debug(output.rstrip('\n'))

    return output
