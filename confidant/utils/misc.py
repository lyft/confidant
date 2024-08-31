import importlib
import pytz
from datetime import datetime


split_cache = {}


def dict_deep_update(a, b):
    """
    Deep merge in place of two dicts. For all keys in `b`, override matching
    keys in `a`. If both `a` and `b` have a dict at a given key, recursively
    update `a`.

    :param a: Left hand side dict to update in place
    :type a: dict

    :param b: Right hand side with values to pull in
    :type b: dict
    """
    for key, val in b.items():
        if isinstance(a.get(key), dict) and isinstance(val, dict):
            dict_deep_update(a[key], val)
        else:
            a[key] = val


def load_module(module_path):
    """ Load's a python module.

    ex: module_path = "confidant.authnz.rbac:no_acl"

    Will load the module confidant.authnz.rbac and return the function no_acl
    """
    module_name, function_name = module_path.split(':')
    module = importlib.import_module(module_name)
    function = getattr(module, function_name)

    return function


def get_boolean(val, default=False):
    """
    Given a value, check if if corresponds to True or False.
    Python's bool() does not behave as expected for strings so we
    have a helper function here
    """
    if val is None:
        return default
    return val in ['True', 'true', '1']


def utcnow():
    """
    Returns the current time with tzinfo='UTC'.
    datetime.utcnow() currently does not populate tzinfo
    """
    now = datetime.utcnow()
    return now.replace(tzinfo=pytz.utc)


def _split_items(items, limit):
    if limit not in split_cache:
        split_cache[limit] = {}
    key = str(items)
    if key not in split_cache[limit]:
        items = sorted(items)
        split_cache[limit][key] = []
        for i in range(0, len(items), limit):
            split_cache[limit][key].append(items[i:i+limit])
    return split_cache[limit][key]


def get_page(items, limit, page):
    # no page specified (first page)
    if page is None:
        page = 1
    pages = _split_items(items, limit)
    total = len(pages)

    # if there is one, calculate next page
    # (consistent with other methods)
    next_page = None
    if page < total:
        next_page = page + 1

    # validate page within range
    if 1 <= page <= total:
        return _split_items(items, limit)[page-1], next_page
    else:
        return [], None
