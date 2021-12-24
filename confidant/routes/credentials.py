import base64
import json
import logging
import re
import uuid

from flask import blueprints, jsonify, request
from pynamodb.exceptions import DoesNotExist, PutError

from confidant import authnz, clients, settings
from confidant.models.credential import Credential
from confidant.schema.credentials import (
    CredentialResponse,
    CredentialsResponse,
    credential_response_schema,
    credentials_response_schema,
    RevisionsResponse,
    revisions_response_schema,
)
from confidant.services import (
    credentialmanager,
    graphite,
    keymanager,
    servicemanager,
    webhook,
)
from confidant.services.ciphermanager import CipherManager
from confidant.utils import maintenance, misc
from confidant.utils.dynamodb import decode_last_evaluated_key

logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('credentials', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)
VALUE_LENGTH = 50


@blueprint.route('/v1/credentials', methods=['GET'])
@authnz.require_auth
def get_credential_list():
    """
    Returns a list of the metadata of all the current revision of credentials.

    .. :quickref: Credentials; Get a list of the metadata for all current
                  credential revisions.

    **Example request**:

    .. sourcecode:: http

       GET /v1/credentials

    :query string next_page: If paged results were returned in a call, this
                             query string can be used to fetch the next page.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "credentials": [
           {
             "id": "abcd12345bf4f1cafe8e722d3860404",
             "name": "Example Credential",
             "credential_keys": [],
             "credential_pairs": {},
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
         next_page: null
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to list credentials.
    """
    if not acl_module_check(resource_type='credential', action='list'):
        msg = "{} does not have access to list credentials".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403

    credentials_response = CredentialsResponse.from_credentials([
        credential
        for credential in Credential.data_type_date_index.query('credential')
    ])
    return credentials_response_schema.dumps(credentials_response)


@blueprint.route('/v1/credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_credential(id):
    """
    Returns a credential object for the provided credential id.

    .. :quickref: Credential; Get a credential from the provided id.

    **Example request**:

    .. sourcecode:: http

       GET /v1/credentials/abcd12345bf4f1cafe8e722d3860404

    :param id: The credential ID to get.
    :type id: str

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "id": "...",
         "name": "Example Credential",
         "credential_keys": [
           "api_key",
           "api_user"
         ],
         "credential_pairs": {
           "api_key": "1234",
           "api_user": "example_user"
         },
         "metadata": {
           "example_metadata_key": "example_value"
         },
         "revision": 1,
         "enabled": true,
         "documentation": "Example documentation",
         "modified_date": "2019-12-16T23:16:11.413299+00:00",
         "modified_by": "rlane@example.com",
         "permissions": {
           "metadata": true,
           "get": true,
           "update": true
         }
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to get the credential for
                     the provided ID.
    :statuscode 404: The provided credential ID does not exist.
    """
    metadata_only = misc.get_boolean(request.args.get('metadata_only'))

    if not acl_module_check(resource_type='credential',
                            action='metadata',
                            resource_id=id):
        msg = "{} does not have access to credential {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    try:
        credential = Credential.get(id)
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if credential.data_type != 'credential':
        return jsonify({}), 404

    permissions = {
        'metadata': True,
        'get': acl_module_check(
            resource_type='credential',
            action='get',
            resource_id=id
        ),
        'update': acl_module_check(
            resource_type='credential',
            action='update',
            resource_id=id
        ),
    }
    include_credential_pairs = False
    if not metadata_only and acl_module_check(resource_type='credential',
                                              action='get',
                                              resource_id=id):
        permissions['get'] = True
        include_credential_pairs = True

        if settings.ENABLE_SAVE_LAST_DECRYPTION_TIME:
            # Also try to save the archived credential to stay consistent
            try:
                archived_credential = Credential.get(
                    '{}-{}'.format(id, credential.revision)
                )
            except DoesNotExist:
                archived_credential = None
                logger.error('Archived credential {}-{} not found'.format(
                        id, credential.revision)
                )
            now = misc.utcnow()
            credential.last_decrypted_date = now
            credential.save()
            if archived_credential:
                archived_credential.last_decrypted_date = now
                archived_credential.save()

        log_line = "{0} get credential {1}".format(
            authnz.get_logged_in_user(),
            id
        )
        logger.info(log_line)

    credential_response = CredentialResponse.from_credential(
        credential,
        include_credential_keys=True,
        include_credential_pairs=include_credential_pairs,
    )
    credential_response.permissions = permissions
    return credential_response_schema.dumps(credential_response)


@blueprint.route(
    '/v1/credentials/<id>/<old_revision>/<new_revision>',
    methods=['GET']
)
@authnz.require_auth
def diff_credential(id, old_revision, new_revision):
    """
    Returns a diff between old_revision and new_revision for the provided
    credential id.

    .. :quickref: Credential Diff; Get a diff of two revisions of a credential.

    **Example request**:

    .. sourcecode:: http

       GET /v1/credentials/abcd12345bf4f1cafe8e722d3860404/1/2

    :param id: The credential ID to get.
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
         "name": {
           "added": "New credential name",
           "removed": "Example credential name"
         },
         "credential_pairs": {
           "added": [
             "api_key",
             "api_user"
           ],
           "removed": [
             "api_certificate"
           ]
         },
         "metadata": {
           "added": "example_key"
         },
         "enabled": {
           "added": false,
           "removed": true
         },
         "documentation": {
           "added": "The way you rotate this credential is to...",
           "removed": "Example documentation"
         },
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
                     credential ID.
    :statuscode 404: The provided credential ID or one of the provided
                     revisions does not exist.
    """
    if not acl_module_check(resource_type='credential',
                            action='metadata',
                            resource_id=id):
        msg = "{} does not have access to diff credential {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    try:
        old_credential = Credential.get('{}-{}'.format(id, old_revision))
    except DoesNotExist:
        return jsonify({'error': 'Credential not found.'}), 404
    if old_credential.data_type != 'archive-credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400
    try:
        new_credential = Credential.get('{}-{}'.format(id, new_revision))
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if new_credential.data_type != 'archive-credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400
    return jsonify(old_credential.diff(new_credential))


@blueprint.route('/v1/archive/credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_credential_revisions(id):
    """
    Returns a list of the metadata of all the revisions of the provided
    credential.

    .. :quickref: Credential Revisions; Get a list of the metadata of all the
                  revisions of the provided credential.

    **Example request**:

    .. sourcecode:: http

       GET /v1/archive/credentials/abcd12345bf4f1cafe8e722d3860404

    :query string next_page: If paged results were returned in a call, this
                             query string can be used to fetch the next page.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "revisions": [
           {
             "id": "abcd12345bf4f1cafe8e722d3860404-1",
             "name": "Example Credential",
             "credential_keys": [],
             "credential_pairs": {},
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
         next_page: null
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to get credential
                     metadata for the provided credential ID.
    :statuscode 404: The provided credential ID does not exist.
    """
    if not acl_module_check(resource_type='credential',
                            action='metadata',
                            resource_id=id):
        msg = "{} does not have access to credential {} revisions".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403

    try:
        cred = Credential.get(id)
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (cred.data_type != 'credential' and
            cred.data_type != 'archive-credential'):
        return jsonify({}), 404
    revisions_response = RevisionsResponse.from_credentials(
        Credential.batch_get(
            credentialmanager.get_revision_ids_for_credential(cred)
        )
    )
    return revisions_response_schema.dumps(revisions_response)


@blueprint.route('/v1/archive/credentials', methods=['GET'])
@authnz.require_auth
def get_archive_credential_list():
    """
    Returns a list of the metadata of all the history revisions of credentials.

    .. :quickref: Credential History; Get a list of the metadata for all history
                  revision credentials.

    **Example request**:

    .. sourcecode:: http

       GET /v1/archive/credentials/abcd12345bf4f1cafe8e722d3860404

    :query string next_page: If paged results were returned in a call, this
                             query string can be used to fetch the next page.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "revisions": [
           {
             "id": "abcd12345bf4f1cafe8e722d3860404-1",
             "name": "Example Credential",
             "credential_keys": [],
             "credential_pairs": {},
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
         next_page: null
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to list credentials
    """
    if not acl_module_check(resource_type='credential', action='list'):
        msg = "{} does not have access to list credentials".format(
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
    results = Credential.data_type_date_index.query(
        'archive-credential',
        scan_index_forward=False,
        limit=limit,
        last_evaluated_key=page,
    )
    credentials_response = CredentialsResponse.from_credentials(
        [credential for credential in results],
        next_page=results.last_evaluated_key,
    )
    return credentials_response_schema.dumps(credentials_response)


@blueprint.route('/v1/credentials', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def create_credential():
    '''
    Create a credential using the data provided in the POST body.

    .. :quickref: Credential; Create a credential using the data provided in
                  the post body.

    **Example request**:

    .. sourcecode:: http

       POST /v1/credentials

    :<json string name: The friendly name for the credential. (required)
    :<json Dictionary{string: string} credential_pairs: A dictionary of
      arbitrary key/value pairs to be encrypted at rest. (required)
    :<json Dictionary{string: string} metadata: A dictionary of arbitrary key/
      value pairs for custom per-credential end-user extensions. This is not
      encrypted at rest.
    :<json boolean enabled: Whether or not this credential is enabled.
      (default: true)
    :<json string documentation: End-user provided documentation for this
      credential. (required)

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

        {
          "id": "abcd12345bf4f1cafe8e722d3860404",
          "name": "Example Credential",
          "credential_keys": ["example_credential_key"],
          "credential_pairs": {
            "example_credential_key": "example_credential_value"
          },
          "metadata": {
            "example_metadata_key": "example_value"
          },
          "revision": 1,
          "enabled": true,
          "documentation": "Example documentation",
          "modified_date": "2019-12-16T23:16:11.413299+00:00",
          "modified_by": "rlane@example.com",
          "permissions": {
            "metadata": true,
            "get": true,
            "update": true
          }
        }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input; either the data provided was not in the
                     correct format, or a required field was not provided.
    :statuscode 403: Client does not have access to create credentials.
    '''
    if not acl_module_check(resource_type='credential', action='create'):
        msg = "{} does not have access to create credentials".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403

    data = request.get_json()
    if not data.get('documentation') and settings.get('ENFORCE_DOCUMENTATION'):
        return jsonify({'error': 'documentation is a required field'}), 400
    if not data.get('credential_pairs'):
        return jsonify({'error': 'credential_pairs is a required field'}), 400
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    # Ensure credential pair keys are lowercase
    credential_pairs = credentialmanager.lowercase_credential_pairs(
        data['credential_pairs']
    )
    _check, ret = credentialmanager.check_credential_pair_values(
        credential_pairs
    )
    if not _check:
        return jsonify(ret), 400
    for cred in Credential.data_type_date_index.query(
            'credential', name__eq=data['name']):
        # Conflict, the name already exists
        msg = 'Name already exists. See id: {0}'.format(cred.id)
        return jsonify({'error': msg, 'reference': cred.id}), 409
    # Generate an initial stable ID to allow name changes
    id = str(uuid.uuid4()).replace('-', '')
    # Try to save to the archive
    revision = 1
    credential_pairs = json.dumps(credential_pairs)
    data_key = keymanager.create_datakey(encryption_context={'id': id})
    cipher = CipherManager(data_key['plaintext'], version=2)
    credential_pairs = cipher.encrypt(credential_pairs)
    last_rotation_date = misc.utcnow()
    cred = Credential(
        id='{0}-{1}'.format(id, revision),
        data_type='archive-credential',
        name=data['name'],
        credential_pairs=credential_pairs,
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation'),
        tags=data.get('tags', []),
        last_rotation_date=last_rotation_date,
    ).save(id__null=True)
    # Make this the current revision
    cred = Credential(
        id=id,
        data_type='credential',
        name=data['name'],
        credential_pairs=credential_pairs,
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation'),
        tags=data.get('tags', []),
        last_rotation_date=last_rotation_date,
    )
    cred.save()
    permissions = {
        'metadata': True,
        'get': True,
        'update': True,
    }
    credential_response = CredentialResponse.from_credential(
        cred,
        include_credential_keys=True,
        include_credential_pairs=True,
    )
    credential_response.permissions = permissions
    return credential_response_schema.dumps(credential_response)


@blueprint.route('/v1/credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_credential_dependencies(id):
    """
    Returns a list of services that this credential is mapped to.

    .. :quickref: Credential Mappings; Get a list of services that this
                  credential is mapped to.

    **Example request**:

    .. sourcecode:: http

       GET /v1/credentials/abcd12345bf4f1cafe8e722d3860404/services

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "services": ["example-development", "example2-development"]
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 403: Client does not have permissions to get metadata for the
                     provided credential.
    """
    if not acl_module_check(resource_type='credential',
                            action='metadata',
                            resource_id=id):
        msg = "{} does not have access to get dependencies for credential {}"
        msg = msg.format(authnz.get_logged_in_user(), id)
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    services = servicemanager.get_services_for_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({'services': _services})


@blueprint.route('/v1/credentials/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def update_credential(id):
    '''
    Update the provided credential using the data provided in the POST body.

    .. :quickref: Credential; Update the provided credential using the data
                  provided in the post body.

    **Example request**:

    .. sourcecode:: http

       PUT /v1/credentials/abcd12345bf4f1cafe8e722d3860404

    :param id: The credential ID to update.
    :type id: str
    :<json string name: The friendly name for the credential.
    :<json Dictionary{string: string} credential_pairs: A dictionary of
      arbitrary key/value pairs to be encrypted at rest.
    :<json Dictionary{string: string} metadata: A dictionary of arbitrary key/
      value pairs for custom per-credential end-user extensions. This is not
      encrypted at rest.
    :<json boolean enabled: Whether or not this credential is enabled.
    :<json string documentation: End-user provided documentation for this
      credential.

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

        {
          "id": "abcd12345bf4f1cafe8e722d3860404",
          "name": "Example Credential",
          "credential_keys": ["example_credential_key"],
          "credential_pairs": {
            "example_credential_key": "example_credential_value"
          },
          "metadata": {
            "example_metadata_key": "example_value"
          },
          "revision": 1,
          "enabled": true,
          "documentation": "Example documentation",
          "modified_date": "2019-12-16T23:16:11.413299+00:00",
          "modified_by": "rlane@example.com",
          "permissions": {
            "metadata": true,
            "get": true,
            "update": true
          }
        }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input; either the data provided was not in the
                     correct format, or the update would create conflicting
                     credential keys in a mapped service.
    :statuscode 403: Client does not have access to update the provided
                     credential ID.
    '''
    if not acl_module_check(resource_type='credential',
                            action='update',
                            resource_id=id):
        msg = "{} does not have access to update credential {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    try:
        _cred = Credential.get(id)
    except DoesNotExist:
        return jsonify({'error': 'Credential not found.'}), 404
    if _cred.data_type != 'credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400

    data = request.get_json()
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400

    update = {
        'name': data.get('name', _cred.name),
        'last_rotation_date': _cred.last_rotation_date,
        'credential_pairs': _cred.credential_pairs,
        'enabled': _cred.enabled,
        'metadata': data.get('metadata', _cred.metadata),
        'documentation': data.get('documentation', _cred.documentation),
        'tags': data.get('tags', _cred.tags),
    }
    # Enforce documentation, EXCEPT if we are restoring an old revision
    if (not update['documentation'] and
            settings.get('ENFORCE_DOCUMENTATION') and
            not data.get('revision')):
        return jsonify({'error': 'documentation is a required field'}), 400
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return jsonify({'error': 'Enabled must be a boolean.'}), 400
        update['enabled'] = data['enabled']

    services = servicemanager.get_services_for_credential(id)
    revision = credentialmanager.get_latest_credential_revision(
        id,
        _cred.revision
    )
    if 'credential_pairs' in data:
        # Ensure credential pair keys are lowercase
        credential_pairs = credentialmanager.lowercase_credential_pairs(
            data['credential_pairs']
        )
        _check, ret = credentialmanager.check_credential_pair_values(
            credential_pairs
        )
        if not _check:
            return jsonify(ret), 400
        # Ensure credential pairs don't conflicts with pairs from other
        # services
        conflicts = servicemanager.pair_key_conflicts_for_services(
            id,
            list(credential_pairs.keys()),
            services
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400

        # If the credential pair passed in the update is different from the
        # decrypted credential pair of the most recent revision, assume that
        # this is a new credential pair and update last_rotation_date
        if credential_pairs != _cred.decrypted_credential_pairs:
            update['last_rotation_date'] = misc.utcnow()
        data_key = keymanager.create_datakey(encryption_context={'id': id})
        cipher = CipherManager(data_key['plaintext'], version=2)
        update['credential_pairs'] = cipher.encrypt(
            json.dumps(credential_pairs)
        )

    # Try to save to the archive
    try:
        Credential(
            id='{0}-{1}'.format(id, revision),
            name=update['name'],
            data_type='archive-credential',
            credential_pairs=update['credential_pairs'],
            metadata=update['metadata'],
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation'],
            tags=update['tags'],
            last_rotation_date=update['last_rotation_date'],
        ).save(id__null=True)
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to add credential to archive.'}), 500
    try:
        cred = Credential(
            id=id,
            name=update['name'],
            data_type='credential',
            credential_pairs=update['credential_pairs'],
            metadata=update['metadata'],
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation'],
            tags=update['tags'],
            last_rotation_date=update['last_rotation_date'],
        )
        cred.save()
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to update active credential.'}), 500

    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
        webhook.send_event('credential_update', service_names, [cred.id])
    permissions = {
        'metadata': True,
        'get': True,
        'update': True,
    }
    credential_response = CredentialResponse.from_credential(
        cred,
        include_credential_keys=True,
        include_credential_pairs=True,
    )
    credential_response.permissions = permissions
    return credential_response_schema.dumps(credential_response)


@blueprint.route('/v1/credentials/<id>/<to_revision>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def revert_credential_to_revision(id, to_revision):
    '''
    Revert the provided credential to the provided revision.

    .. :quickref: Credential; Revert the provided credential to the provided
                  revision

    **Example request**:

    .. sourcecode:: http

       PUT /v1/credentials/abcd12345bf4f1cafe8e722d3860404/1

    :param id: The credential ID to revert.
    :type id: str
    :param to_revision: The revision to revert this credential to.
    :type to_revision: int

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

        {
          "id": "abcd12345bf4f1cafe8e722d3860404",
          "name": "Example Credential",
          "credential_keys": ["example_credential_key"],
          "credential_pairs": {},
          "metadata": {
            "example_metadata_key": "example_value"
          },
          "revision": 1,
          "enabled": true,
          "documentation": "Example documentation",
          "modified_date": "2019-12-16T23:16:11.413299+00:00",
          "modified_by": "rlane@example.com",
          "permissions": {
            "metadata": true,
            "get": true,
            "update": true
          }
        }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    :statuscode 400: Invalid input; the update would create conflicting
                     credential keys in a mapped service.
    :statuscode 403: Client does not have access to revert the provided
                     credential ID.
    '''
    if not acl_module_check(resource_type='credential',
                            action='revert',
                            resource_id=id):
        msg = "{} does not have access to revert credential {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
        return jsonify(error_msg), 403

    try:
        current_credential = Credential.get(id)
    except DoesNotExist:
        return jsonify({'error': 'Credential not found.'}), 404
    if current_credential.data_type != 'credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400
    new_revision = credentialmanager.get_latest_credential_revision(
        id,
        current_credential.revision
    )
    try:
        revert_credential = Credential.get('{}-{}'.format(id, to_revision))
    except DoesNotExist:
        logger.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if revert_credential.data_type != 'archive-credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400
    if revert_credential.equals(current_credential):
        ret = {
            'error': 'No difference between old and new credential.'
        }
        return jsonify(ret), 400
    services = servicemanager.get_services_for_credential(id)
    if revert_credential.credential_pairs:
        _credential_pairs = revert_credential.decrypted_credential_pairs
        _check, ret = credentialmanager.check_credential_pair_values(
            _credential_pairs
        )
        if not _check:
            return jsonify(ret), 400
        # Ensure credential pairs don't conflicts with pairs from other
        # services
        conflicts = servicemanager.pair_key_conflicts_for_services(
            id,
            list(_credential_pairs.keys()),
            services
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400
    # Try to save to the archive
    try:
        Credential(
            id='{0}-{1}'.format(id, new_revision),
            name=revert_credential.name,
            data_type='archive-credential',
            credential_pairs=revert_credential.credential_pairs,
            metadata=revert_credential.metadata,
            enabled=revert_credential.enabled,
            revision=new_revision,
            data_key=revert_credential.data_key,
            cipher_version=revert_credential.cipher_version,
            modified_by=authnz.get_logged_in_user(),
            documentation=revert_credential.documentation,
            tags=revert_credential.tags,
            last_rotation_date=revert_credential.last_rotation_date,
        ).save(id__null=True)
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to add credential to archive.'}), 500
    try:
        cred = Credential(
            id=id,
            name=revert_credential.name,
            data_type='credential',
            credential_pairs=revert_credential.credential_pairs,
            metadata=revert_credential.metadata,
            enabled=revert_credential.enabled,
            revision=new_revision,
            data_key=revert_credential.data_key,
            cipher_version=revert_credential.cipher_version,
            modified_by=authnz.get_logged_in_user(),
            documentation=revert_credential.documentation,
            tags=revert_credential.tags,
            last_rotation_date=revert_credential.last_rotation_date,
        )
        cred.save()
    except PutError as e:
        logger.error(e)
        return jsonify({'error': 'Failed to update active credential.'}), 500
    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
        webhook.send_event('credential_update', service_names, [cred.id])
    return credential_response_schema.dumps(
        CredentialResponse.from_credential(cred)
    )


@blueprint.route('/v1/value_generator', methods=['GET'])
def generate_value():
    """
    Returns a randomly generated value, for use in credential pairs.

    .. :quickref: Random Value; Get a randomly generated value, for use in
                  credential pairs.

    **Example request**:

    .. sourcecode:: http

       GET /v1/value_generator

    **Example response**:

    .. sourcecode:: http

       HTTP/1.1 200 OK
       Content-Type: application/json

       {
         "value": "c5S0w08YwU4PY3EZ7eQf4QYYUIT6ryyKOydhjyTti9pjPuMU00"
       }

    :resheader Content-Type: application/json
    :statuscode 200: Success
    """
    kms_client = clients.get_boto_client('kms', endpoint_url=settings.KMS_URL)
    value = kms_client.generate_random(NumberOfBytes=128)['Plaintext']
    value = base64.urlsafe_b64encode(value).decode('UTF-8')
    value = re.sub(r'[\W_]+', '', value)
    if len(value) > VALUE_LENGTH:
        value = value[:VALUE_LENGTH]
    return jsonify({'value': value})
