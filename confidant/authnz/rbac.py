
def no_acl(*args, **kwargs):
    """ Stub function that always returns true
    This function is set by settings.py by the variable ACL_MODULE
    When you'd like to integrate a custom RBAC module, the ACL_MODULE
    should be repointed from this function to the function that will perform
    the ACL checks.
    """
    return True
