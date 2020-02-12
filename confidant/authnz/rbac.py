from confidant import authnz


def default_acl(*args, **kwargs):
    """ Default ACLs for confidant: always return true for users, but enforce
    ACLs for services, restricting access to:

    * resource_type: service
      actions: metadata, get
    """
    resource_type = kwargs.get('resource_type')
    action = kwargs.get('action')
    resource_id = kwargs.get('resource_id')
    # Some ACL checks also pass extra args in via kwargs, which we would
    # access via:
    #    resource_kwargs = kwargs.get('kwargs')
    if authnz.user_is_user_type('user'):
        return True
    elif authnz.user_is_user_type('service'):
        if resource_type == 'service' and action in ['metadata', 'get']:
            # Does the resource ID match the authenticated username?
            if authnz.user_is_service(resource_id):
                return True
        # We currently only allow services to access service get/metadata
        return False
    else:
        # This should never happen, but paranoia wins out
        return False


def no_acl(*args, **kwargs):
    """ Stub function that always returns true
    This function is set by settings.py by the variable ACL_MODULE
    When you'd like to integrate a custom RBAC module, the ACL_MODULE
    should be repointed from this function to the function that will perform
    the ACL checks.
    """
    return True
