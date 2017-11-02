from collections import OrderedDict

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
