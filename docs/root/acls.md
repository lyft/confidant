# Access Controls (ACLs)
# CRTODO: add documentation
## Design

The design for managing fine-grained ACLs in confidant is relatively simple. Hookpoints are called whenever a resource type will be accessed by an end-user; these hookpoints look like:

```python
check = acl_module_check(
    resource_type='credential',
    action='metadata',
    resource_id=id,
)
if not check:
    ...
```

Some hookpoints include extra information, via kwargs:

```python
check = acl_module_check(
    resource_type='service',
    action='update',
    resource_id=id,
    kwargs={
        'credential_ids': combined_cred_ids,
    },
)
if not check:
    ...
```

These hookpoints all call back to the same function, which by default is:

```python
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
```

This function is defined by the `ACL_MODULE` setting, which by default is `confidant.authnz.rbac:default_acl`. The format is `python.path.to.module:function_in_module`. You can use this to implement an ACL approach that integrates with your own enviroment, or adjusts confidant's behavior to your needs.

When implementing a new ACL module, remember that there's two types of users: `user` and `service`. By default `service` users are through kmsauth, whereas `user` users can come through kmsauth, or through one of the other forms of auth intended for the UI. You need to implement ACLs for both user types. Additionally, you should likely default your return to False, unless you're intending to only restrict features.

## ACL Hookpoints

The following hookpoints are currently available:

### Credentials

#### List credentials

```python
acl_module_check(resource_type='credential', action='list')
```

This check controls access to lists of credential metadata.

#### Get credential metadata

```python
acl_module_check(
    resource_type='credential',
    action='metadata',
    resource_id=id,
)
```

This check controls access to specific credential metadata, which does not include credential pairs. Fine-grained controls can be applied using the provided `resource_id`.

#### Get credential

```python
acl_module_check(
    resource_type='credential',
    action='get',
    resource_id=id,
)
```

This check controls access to specific credentials, which includes credential pairs. Fine-grained controls can be applied using the provided `resource_id`.

#### Create credential

```python
acl_module_check(
    resource_type='credential',
    action='create',
)
```

This check controls create access to credentials. This is a global permission, so no fine-grained ID is provided.

#### Update credential

```python
acl_module_check(
    resource_type='credential',
    action='update',
    resource_id=id,
)
```

This check controls update access to specific credentials. Fine-grained controls can be applied using the provided `resource_id`. Note that if you're controlling access to this, you probably also want to control access to [Revert credential](#revert-credential).

#### Revert credential

```python
acl_module_check(
    resource_type='credential',
    action='revert',
    resource_id=id,
)
```

This check controls revert access to specific credentials. Fine-grained controls can be applied using the provided `resource_id`. Note that if you're controlling access to this, you probably also want to control access to [Update credential](#update-credential).

This action does not require access to view or edit credential pairs, so it can be used to allow folks to rollback changes to resources without access to view/edit them.

### Services

#### List services

```python
acl_module_check(resource_type='service', action='list')
```

This check controls access to lists of service metadata.

#### Get service metadata

```python
acl_module_check(
    resource_type='service',
    action='metadata',
    resource_id=id,
)
```

This check controls access to specific service metadata, which includes service data, and credential metadata, for credentials that are mapped to the service, but does not include credential pairs in the credentials. Fine-grained controls can be applied using the provided `resource_id`.

#### Get service

```python
acl_module_check(
    resource_type='service',
    action='get',
    resource_id=id,
)
```

This check controls access to specific service data, which includes service data, and credential that are mapped to the service, including credential pairs in the credentials. Fine-grained controls can be applied using the provided `resource_id`.

#### Create service

```python
acl_module_check(
    resource_type='service',
    action='create',
    resource_id=id,
)
```

This check controls create access to specific services. Fine-grained controls can be applied using the provided `resource_id`.

#### Update service

```python
acl_module_check(
    resource_type='service',
    action='update',
    resource_id=id,
)
```

This check controls update access to specific services. Fine-grained controls can be applied using the provided `resource_id`. Note that if you're controlling access to this, you probably also want to control access to [Revert service](#revert-service).

#### Revert service

```python
acl_module_check(
    resource_type='service',
    action='revert',
    resource_id=id,
)
```

This check controls revert access to specific services. Fine-grained controls can be applied using the provided `resource_id`. Note that if you're controlling access to this, you probably also want to control access to [Update service](#update-service).

This action does not require access to view or update services, so it can be used to allow folks to rollback changes to resources without access to view/update them.
