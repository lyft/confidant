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
    for key, val in b.iteritems():
        if isinstance(a.get(key), dict) and isinstance(val, dict):
            dict_deep_update(a[key], val)
        else:
            a[key] = val
