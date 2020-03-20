import logging

from flask import blueprints, jsonify, request
from pynamodb.exceptions import DoesNotExist, PutError

from confidant import authnz, settings
from confidant.models.service import Service
from confidant.schema.services import (
    ServiceResponse,
    ServicesResponse,
    service_expanded_response_schema,
    services_response_schema,
    RevisionsResponse,
    revisions_response_schema,
)
from confidant.services import (
    credentialmanager,
    iamrolemanager,
    keymanager,
    servicemanager,
    webhook,
)
from confidant.utils import maintenance, misc
from confidant.utils.dynamodb import decode_last_evaluated_key

logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('services', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@blueprint.route('/v1/roles', methods=['GET'])
@authnz.require_auth
def get_iam_roles_list():
    """
    Get a list of IAM roles from the configured AWS account.

    .. :quickref: IAM Roles; Get a list of IAM roles from the configured
                  AWS account.

    **Example request**:

    .. sourcecode:: http

       GET /v1/roles

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "roles": [
           'example-development',
           'example2-development',
           ...
         ]
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to list services.
    """
    if not acl_module_check(resource_type='service',
                            action='list'):
        msg = "{} does not have access to list services".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403

    roles = iamrolemanager.get_iam_roles()
    return jsonify({'roles': roles})


@blueprint.route('/v1/services', methods=['GET'])
@authnz.require_auth
def get_service_list():
    """
    Get a list of current service revisions.

    .. :quickref: Services; Get a list of current service revisions.

    **Example request**:

    .. sourcecode:: http

       GET /v1/services

    :query string next_page: If paged results were returned in a call, this
                             query string can be used to fetch the next page.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "services": [
           {
             "id": "example-development",
             "revision": 1,
             "enabled": true,
             "modified_date": "2019-12-16T23:16:11.413299+00:00",
             "modified_by": "rlane@example.com",
             "account": null,
             "credentials": [],
             "blind_credentials": [],
             "permissions": {}
           },
           ...
         ],
         "next_page": null
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to list services.
    """
    if not acl_module_check(resource_type='service',
                            action='list'):
        msg = "{} does not have access to list services".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403
    services_response = ServicesResponse.from_services(
        Service.data_type_date_index.query('service')
    )
    return services_response_schema.dumps(services_response)


@blueprint.route('/v1/services/<id>', methods=['GET'])
@authnz.require_auth
def get_service(id):
    '''
    Get a service object from the provided service ID.

    .. :quickref: Service; Get a service object from the provided service ID.

    **Example request**:

    .. sourcecode:: http

       GET /v1/services/example-development

    :param id: The service ID to get.
    :type id: str
    :query boolean metadata_only: If true, only fetch metadata for this
      service, and do not respond with decrypted credential pairs in the
      credential responses.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "id": "example-development",
         "revision": 1,
         "enabled": true,
         "modified_date": "2019-12-16T23:16:11.413299+00:00",
         "modified_by": "rlane@example.com",
         "account": null,
         "credentials": [
           {
             "id": "abcd12345bf4f1cafe8e722d3860404",
             "name": "Example Credential",
             "credential_keys": ["test_key"],
             "credential_pairs": {
               "test_key": "test_value"
             },
             "metadata": {
               "example_metadata_key": "example_value"
             },
             "revision": 1,
             "enabled": true,
             "documentation": "Example documentation",
             "modified_date": "2019-12-16T23:16:11.413299+00:00",
             "modified_by": "rlane@example.com",
             "permissions": {}
           },
           ...
         ],
         "blind_credentials": [],
         "permissions": {
           "metadata": true,
           "get": true,
           "update": true
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to get the service ID
                     provided.
    '''
    permissions = {
        'metadata': False,
        'get': False,
        'update': False,
    }
    metadata_only = misc.get_boolean(request.args.get('metadata_only'))
    logged_in_user = authnz.get_logged_in_user()
    action = 'metadata' if metadata_only else 'get'
    permissions['metadata'] = acl_module_check(
        resource_type='service',
        action='metadata',
        resource_id=id,
    )
    permissions['get'] = acl_module_check(
        resource_type='service',
        action='get',
        resource_id=id,
    )
    if not permissions[action]:
        msg = "{} does not have access to get service {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    logger.info(
        'get_service called on id={} by user={} metadata_only={}'.format(
            id,
            logged_in_user,
            metadata_only,
        )
    )
    try:
        service = Service.get(id)
        if not authnz.service_in_account(service.account):
            logger.warning(
                'Authz failed for service {0} (wrong account).'.format(id)
            )
            msg = 'Authenticated user is not authorized.'
            return jsonify({'error': msg}), 401
    except DoesNotExist:
        return jsonify({}), 404
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    logger.debug('Authz succeeded for service {0}.'.format(id))
    try:
        credentials = credentialmanager.get_credentials(service.credentials)
    except KeyError:
        logger.exception('KeyError occurred in getting credentials')
        return jsonify({'error': 'Decryption error.'}), 500
    blind_credentials = credentialmanager.get_blind_credentials(
        service.blind_credentials,
    )
    # TODO: this check can be expensive, so we're gating only to user auth.
    # We should probably add an argument that opts in for permission hints,
    # rather than always checking them.
    if authnz.user_is_user_type('user'):
        combined_cred_ids = (
            list(service.credentials) + list(service.blind_credentials)
        )
        permissions['update'] = acl_module_check(
            resource_type='service',
            action='update',
            resource_id=id,
            kwargs={
                'credential_ids': combined_cred_ids,
            },
        )
    service_response = ServiceResponse.from_service_expanded(
        service,
        credentials=credentials,
        blind_credentials=blind_credentials,
        metadata_only=metadata_only,
    )
    service_response.permissions = permissions
    return service_expanded_response_schema.dumps(service_response)


@blueprint.route('/v1/archive/services/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_service_revisions(id):
    """
    Get a list of revisions for the specified service ID.

    .. :quickref: Service History; Get a list of revisions for the specified
                  service ID.

    **Example request**:

    .. sourcecode:: http

       GET /v1/archive/services/example-development

    :param id: The service ID to get.
    :type id: str
    :query string next_page: If paged results were returned in a call, this
                             query string can be used to fetch the next page.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "revisions": [
           {
             "id": "example-development-1",
             "revision": 1,
             "enabled": true,
             "modified_date": "2019-12-16T23:16:11.413299+00:00",
             "modified_by": "rlane@example.com",
             "account": null,
             "credentials": [],
             "blind_credentials": [],
             "permissions": {}
           },
           ...
         ],
         "next_page": null
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to get metadata for the
                     provided service ID.
    :statuscode 404: Specified ID does not exist.
    """
    if not acl_module_check(resource_type='service',
                            action='metadata',
                            resource_id=id):
        msg = "{} does not have access to service {} revisions".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403
    try:
        service = Service.get(id)
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    _range = range(1, service.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    revisions_response = RevisionsResponse.from_services(
        Service.batch_get(ids)
    )
    return revisions_response_schema.dumps(revisions_response)


@blueprint.route('/v1/archive/services', methods=['GET'])
@authnz.require_auth
def get_archive_service_list():
    """
    Get a list of service history revisions.

    .. :quickref: Service History; Get a list of service history revisions.

    **Example request**:

    .. sourcecode:: http

       GET /v1/archive/services

    :query string next_page: If paged results were returned in a call, this
                             query string can be used to fetch the next page.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "services": [
           {
             "id": "example-development-1",
             "revision": 1,
             "enabled": true,
             "modified_date": "2019-12-16T23:16:11.413299+00:00",
             "modified_by": "rlane@example.com",
             "account": null,
             "credentials": [],
             "blind_credentials": [],
             "permissions": {}
           },
           ...
         ],
         "next_page": null
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to list services.
    """
    if not acl_module_check(resource_type='service',
                            action='list'):
        msg = "{} does not have access to list services".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403
    limit = request.args.get(
        'limit',
        default=settings.HISTORY_PAGE_LIMIT,
        type=int,
    )
    page = request.args.get('page', default=None, type=str)
    if page:
        try:
            page = decode_last_evaluated_key(page)
        except Exception:
            logger.exception('Failed to parse provided page')
            return jsonify({'error': 'Failed to parse page'}), 400
    results = Service.data_type_date_index.query(
        'archive-service',
        scan_index_forward=False,
        limit=limit,
        last_evaluated_key=page,
    )
    services_response = ServicesResponse.from_services(
        [service for service in results],
        next_page=results.last_evaluated_key,
    )
    return services_response_schema.dumps(services_response)


@blueprint.route('/v1/services/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def map_service_credentials(id):
    """
    Create or update a service to credential mapping.

    .. :quickref: Service; Create or update a service to credential mapping
                  with the data provided in the PUT body.

    **Example request**:

    .. sourcecode:: http

       PUT /v1/services/example-development

    :param id: The service ID to create or update.
    :type id: str
    :<json List[string] credentials: A list of credential IDs to map to this
      service.
    :<json List[string] blind_credentials: A list of blind_credential IDs to
      map to this service.
    :<json boolean enabled: Whether or not this service is enabled.
      (default: true)
    :<json string account: An AWS account to scope this service to.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "id": "example-development",
         "revision": 1,
         "enabled": true,
         "modified_date": "2019-12-16T23:16:11.413299+00:00",
         "modified_by": "rlane@example.com",
         "account": null,
         "credentials": [
           {
             "id": "abcd12345bf4f1cafe8e722d3860404",
             "name": "Example Credential",
             "credential_keys": ["test_key"],
             "credential_pairs": {
               "test_key": "test_value"
             },
             "metadata": {
               "example_metadata_key": "example_value"
             },
             "revision": 1,
             "enabled": true,
             "documentation": "Example documentation",
             "modified_date": "2019-12-16T23:16:11.413299+00:00",
             "modified_by": "rlane@example.com",
             "permissions": {}
           },
           ...
         ],
         "blind_credentials": [],
         "permissions": {}
           "metadata": True,
           "get": True,
           "update": True
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input; Either required fields were not provided
                     or credentials being mapped would result in credential key
                     conflicts.
    :statuscode 403: Client does not have permissions to create or update the
                     specified service ID.
    """
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
        revision = servicemanager.get_latest_service_revision(
            id,
            _service.revision
        )
    except DoesNotExist:
        revision = 1
        _service = None

    if revision == 1 and not acl_module_check(
          resource_type='service',
          action='create',
          resource_id=id,
    ):
        msg = "{} does not have access to create service {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    data = request.get_json()
    credentials = data.get('credentials', [])
    blind_credentials = data.get('blind_credentials', [])
    combined_credentials = credentials + blind_credentials
    if not acl_module_check(
          resource_type='service',
          action='update',
          resource_id=id,
          kwargs={
              'credential_ids': combined_credentials,
          }
    ):
        msg = ("{} does not have access to map the credentials "
               "because they do not own the credentials being added")
        msg = msg.format(authnz.get_logged_in_user())
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    conflicts = credentialmanager.pair_key_conflicts_for_credentials(
        credentials,
        blind_credentials,
    )
    if conflicts:
        ret = {
            'error': 'Conflicting key pairs in mapped service.',
            'conflicts': conflicts
        }
        return jsonify(ret), 400

    accounts = list(settings.SCOPED_AUTH_KEYS.values())
    if data.get('account') and data['account'] not in accounts:
        ret = {'error': '{0} is not a valid account.'}
        return jsonify(ret), 400

    # If this is the first revision, we should attempt to create a grant for
    # this service.
    if revision == 1:
        try:
            keymanager.ensure_grants(id)
        except keymanager.ServiceCreateGrantError:
            msg = 'Failed to add grants for {0}.'.format(id)
            logger.error(msg)
    credentials = credentialmanager.get_credentials(data.get('credentials'))
    blind_credentials = credentialmanager.get_blind_credentials(
        data.get('blind_credentials'),
    )
    # Use the IDs from the fetched IDs, to ensure we filter any archived
    # credential IDs.
    filtered_credential_ids = [cred.id for cred in credentials]
    # Try to save to the archive
    try:
        Service(
            id='{0}-{1}'.format(id, revision),
            data_type='archive-service',
            credentials=filtered_credential_ids,
            blind_credentials=data.get('blind_credentials'),
            account=data.get('account'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user()
        ).save(id__null=True)
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to add service to archive.'}), 500

    try:
        service = Service(
            id=id,
            data_type='service',
            credentials=filtered_credential_ids,
            blind_credentials=data.get('blind_credentials'),
            account=data.get('account'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user()
        )
        service.save()
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to update active service.'}), 500
    servicemanager.send_service_mapping_graphite_event(service, _service)
    webhook.send_event('service_update', [service.id], service.credentials)
    permissions = {
        'create': True,
        'metadata': True,
        'get': True,
        'update': True,
    }
    service_response = ServiceResponse.from_service_expanded(
        service,
        credentials=credentials,
        blind_credentials=blind_credentials,
    )
    service_response.permissions = permissions
    return service_expanded_response_schema.dumps(service_response)


@blueprint.route('/v1/services/<id>/<to_revision>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def revert_service_to_revision(id, to_revision):
    '''
    Revert the provided service to the provided revision.

    .. :quickref: Service; Revert the provided service to the provided
                  revision

    **Example request**:

    .. sourcecode:: http

       PUT /v1/services/example-development/1

    :param id: The service ID to revert.
    :type id: str
    :param to_revision: The revision to revert this service to.
    :type to_revision: int

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "id": "abcd12345bf4f1cafe8e722d3860404",
         "name": "Example Credential",
         "credential_keys": ["test_key"],
         "credential_pairs": {
           "test_key": "test_value"
         },
         "metadata": {
           "example_metadata_key": "example_value"
         },
         "revision": 1,
         "enabled": true,
         "documentation": "Example documentation",
         "modified_date": "2019-12-16T23:16:11.413299+00:00",
         "modified_by": "rlane@example.com",
         "permissions": {}
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input; the update would create conflicting
                     credential keys in the service mapping.
    :statuscode 403: Client does not have access to revert the provided
                     service ID.
    '''
    if not acl_module_check(resource_type='service',
                            action='revert',
                            resource_id=id):
        msg = "{} does not have access to revert service {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    try:
        current_service = Service.get(id)
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if current_service.data_type != 'service':
        msg = 'id provided is not a service.'
        return jsonify({'error': msg}), 400
    new_revision = servicemanager.get_latest_service_revision(
        id,
        current_service.revision
    )
    try:
        revert_service = Service.get('{}-{}'.format(id, to_revision))
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if revert_service.data_type != 'archive-service':
        msg = 'id provided is not a service.'
        return jsonify({'error': msg}), 400
    if revert_service.credentials or revert_service.blind_credentials:
        conflicts = credentialmanager.pair_key_conflicts_for_credentials(
            revert_service.credentials,
            revert_service.blind_credentials,
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400
    credentials = credentialmanager.get_credentials(
        revert_service.credentials,
    )
    blind_credentials = credentialmanager.get_blind_credentials(
        revert_service.blind_credentials,
    )
    # Use the IDs from the fetched IDs, to ensure we filter any archived
    # credential IDs.
    revert_service.credentials = [cred.id for cred in credentials]
    if revert_service.equals(current_service):
        ret = {
            'error': 'No difference between old and new service.'
        }
        return jsonify(ret), 400
    # Try to save to the archive
    try:
        Service(
            id='{0}-{1}'.format(id, new_revision),
            data_type='archive-service',
            credentials=revert_service.credentials,
            blind_credentials=revert_service.blind_credentials,
            account=revert_service.account,
            enabled=revert_service.enabled,
            revision=new_revision,
            modified_by=authnz.get_logged_in_user()
        ).save(id__null=True)
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to add service to archive.'}), 500

    try:
        service = Service(
            id=id,
            data_type='service',
            credentials=revert_service.credentials,
            blind_credentials=revert_service.blind_credentials,
            account=revert_service.account,
            enabled=revert_service.enabled,
            revision=new_revision,
            modified_by=authnz.get_logged_in_user()
        )
        service.save()
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to update active service.'}), 500
    servicemanager.send_service_mapping_graphite_event(service, current_service)
    webhook.send_event(
        'service_update',
        [service.id],
        service.credentials,
    )
    return service_expanded_response_schema.dumps(
        ServiceResponse.from_service_expanded(
            service,
            credentials=credentials,
            blind_credentials=blind_credentials,
        )
    )


@blueprint.route(
    '/v1/services/<id>/<old_revision>/<new_revision>',
    methods=['GET']
)
@authnz.require_auth
def diff_service(id, old_revision, new_revision):
    """
    Returns a diff between old_revision and new_revision for the provided
    service id.

    .. :quickref: Service Diff; Get a diff of two revisions of a service.

    **Example request**:

    .. sourcecode:: http

       GET /v1/services/example-development/1/2

    :param id: The service ID to get.
    :type id: str
    :param old_revision: One of the two revisions to diff against.
    :type old_revision: int
    :param new_revision: One of the two revisions to diff against.
    :type new_revision: int

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "enabled": {
           "added": true,
           "removed": false
         },
         "credentials": {
           "added": [
             "abcd12345bf4f1cafe8e722d3860404"
           ],
           "removed": [
             "aaaa33335bf4f1cafe8e722d3860404"
           ]
         },
         "blind_credentials": {},
         "modified_date": {
           "added": "2019-12-16T23:16:11.413299+00:00",
           "removed": "2019-11-16T23:16:11.413299+00:00"
         },
         "modified_by": {
           "added": "rlane@example.com",
           "removed": "testuser@example.com"
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to diff the provided
                     service ID.
    :statuscode 404: The provided service ID or one of the provided
                     revisions does not exist.
    """
    if not acl_module_check(resource_type='service',
                            action='metadata',
                            resource_id=id):
        msg = "{} does not have access to diff service {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    try:
        old_service = Service.get('{}-{}'.format(id, old_revision))
    except DoesNotExist:
        return jsonify({'error': 'Service not found.'}), 404
    if old_service.data_type != 'archive-service':
        msg = 'id provided is not a service.'
        return jsonify({'error': msg}), 400
    try:
        new_service = Service.get('{}-{}'.format(id, new_revision))
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if new_service.data_type != 'archive-service':
        msg = 'id provided is not a service.'
        return jsonify({'error': msg}), 400
    return jsonify(old_service.diff(new_service))


@blueprint.route('/v1/grants/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def ensure_grants(id):
    """
    Ensure grants are set for the provided service ID.

    .. :quickref: KMS Grants; Ensure grants are set for the provided service ID.

    **Example request**:

    .. sourcecode:: http

       PUT /v1/grants/example-development

    :param id: The service ID to ensure grants for.
    :type id: str

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "id": "example-development",
         "grants": {
           "encrypt_grant": true,
           "decrypt_grant": true
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input. The service provided does not exist.
    :statuscode 403: Client does not have permissions to create or update the
                     specified service ID.
    """
    # we pass [] in for the credential IDs, because this action isn't related
    # to adding or removing credentials, but just a generic update of a
    # service.
    if not acl_module_check(
          resource_type='service',
          action='update',
          resource_id=id,
          kwargs={
              'credential_ids': [],
          }
    ):
        msg = "{} does not have access to ensure grants for service {}"
        msg = msg.format(authnz.get_logged_in_user(), id)
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
    except DoesNotExist:
        msg = 'id provided does not exist.'
        return jsonify({'error': msg}), 400
    try:
        keymanager.ensure_grants(id)
    except keymanager.ServiceCreateGrantError:
        msg = 'Failed to add grants for service.'
        logger.error(msg)
        return jsonify({'error': msg}), 400
    try:
        grants = keymanager.grants_exist(id)
    except keymanager.ServiceGetGrantError:
        msg = 'Failed to get grants.'
        return jsonify({'error': msg}), 500
    return jsonify({
        'id': id,
        'grants': grants
    })


@blueprint.route('/v1/grants/<id>', methods=['GET'])
@authnz.require_auth
def get_grants(id):
    """
    Get grants for the provided service ID.

    .. :quickref: KMS Grants; Get grants for the provided service ID.

    **Example request**:

    .. sourcecode:: http

       GET /v1/grants/example-development

    :param id: The service ID to ensure grants for.
    :type id: str

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "id": "example-development",
         "grants": {
           "encrypt_grant": true,
           "decrypt_grant": true
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input. The service provided does not exist.
    :statuscode 403: Client does not have permissions to get service metadata
                     for the specified service ID.
    """
    if not acl_module_check(
          resource_type='service',
          action='metadata',
          resource_id=id,
    ):
        msg = "{} does not have access to get grants for service {}"
        msg = msg.format(authnz.get_logged_in_user(), id)
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
    except DoesNotExist:
        msg = 'id provided does not exist.'
        return jsonify({'error': msg}), 400
    try:
        grants = keymanager.grants_exist(id)
    except keymanager.ServiceGetGrantError:
        msg = 'Failed to get grants.'
        return jsonify({'error': msg}), 500
    return jsonify({
        'id': id,
        'grants': grants
    })
