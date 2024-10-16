import re

from confidant import authnz
from confidant.services import certificatemanager


def default_acl(*args, **kwargs):
    """ Default ACLs for confidant: Allow access to all resource types
    and actions for users, except for certificate resource_type. Deny access
    to all resource types and actions for services, except:

    * resource_type: service
      actions: metadata, get
      resource_id: must match logged-in user's username
    * resource_type: certificate
      actions: get
      resource_id: must match against ACM_PRIVATE_CA_DOMAIN_REGEX setting
          for the CA for the CN in the CSR, and for all SAN values in the CSR,
          and the server_name named group in the regex must match the logged
          in user's username.
      kwargs (ca): CA used for this get
      kwargs (san): A list of subject alternative names in the CSR
    """
    resource_type = kwargs.get('resource_type')
    action = kwargs.get('action')
    resource_id = kwargs.get('resource_id')
    resource_kwargs = kwargs.get('kwargs')
    if authnz.user_is_user_type('user'):
        if resource_type == 'certificate':
            return False
        elif resource_type == 'ca':
            return False
        return True
    elif authnz.user_is_user_type('service'):
        if resource_type == 'service' and action in ['metadata', 'get']:
            # Does the resource ID match the authenticated username?
            if authnz.user_is_service(resource_id):
                return True
        elif resource_type == 'ca' and action in ['list', 'get']:
            return True
        elif resource_type == 'certificate' and action in ['get']:
            ca_object = certificatemanager.get_ca(resource_kwargs.get('ca'))
            # Require a name pattern
            if not ca_object.settings['name_regex']:
                return False
            cert_pattern = re.compile(ca_object.settings['name_regex'])
            domains = [resource_id]
            domains.extend(resource_kwargs.get('san', []))
            # Ensure the CN and every value in the SAN is allowed for this
            # user.
            for domain in domains:
                match = cert_pattern.match(domain)
                if not match:
                    return False
                service_name = match.group('service_name')
                if not service_name:
                    return False
                if not authnz.user_is_service(service_name):
                    return False
            return True
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
