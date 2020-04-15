import importlib
import pytz
from datetime import datetime


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
