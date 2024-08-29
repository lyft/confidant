import importlib
import pytz
from datetime import datetime
from os import getenv


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


def bool_env(var_name, default=False):
    """
    Get an environment variable coerced to a boolean value.
    Example:
        Bash:
            $ export SOME_VAL=True
        settings.py:
            SOME_VAL = bool_env('SOME_VAL', False)
    Arguments:
        var_name: The name of the environment variable.
        default: The default to use if `var_name` is not specified in the
                 environment.
    Returns: `var_name` or `default` coerced to a boolean using the following
        rules:
            "False", "false" or "" => False
            Any other non-empty string => True
    """
    test_val = getenv(var_name, default)
    # Explicitly check for 'False', 'false', and '0' since all non-empty
    # string are normally coerced to True.
    if test_val in ('False', 'false', '0'):
        return False
    return bool(test_val)


def float_env(var_name, default=0.0):
    """
    Get an environment variable coerced to a float value.
    This has the same arguments as bool_env. If a value cannot be coerced to a
    float, a ValueError will be raised.
    """
    return float(getenv(var_name, default))


def int_env(var_name, default=0):
    """
    Get an environment variable coerced to an integer value.
    This has the same arguments as bool_env. If a value cannot be coerced to an
    integer, a ValueError will be raised.
    """
    return int(getenv(var_name, default))


def str_env(var_name, default=''):
    """
    Get an environment variable as a string.
    This has the same arguments as bool_env.
    """
    return getenv(var_name, default)
