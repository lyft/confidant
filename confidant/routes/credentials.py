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


blueprint = blueprints.Blueprint('credentials', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)
VALUE_LENGTH = 50


@blueprint.route('/v1/credentials', methods=['GET'])
@authnz.require_auth
def get_credential_list():
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
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (credential.data_type != 'credential' and
            credential.data_type != 'archive-credential'):
        return jsonify({}), 404

    permissions = {
        'metadata': True,
        'get': False,
        'update': acl_module_check(
            resource_type='credential',
            action='update',
            resource_id=id
        ),
    }
    include_credential_pairs = False
    if acl_module_check(resource_type='credential',
                        action='get',
                        resource_id=id):
        permissions['get'] = True
        include_credential_pairs = True
        log_line = "{0} get credential {1}".format(
            authnz.get_logged_in_user(),
            id
        )
        logging.info(log_line)
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
        logging.warning(
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
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (cred.data_type != 'credential' and
            cred.data_type != 'archive-credential'):
        return jsonify({}), 404
    _range = range(1, cred.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    revisions_response = RevisionsResponse.from_credentials(
        Credential.batch_get(ids)
    )
    return revisions_response_schema.dumps(revisions_response)


@blueprint.route('/v1/archive/credentials', methods=['GET'])
@authnz.require_auth
def get_archive_credential_list():
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
            logging.exception('Failed to parse provided page')
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
        documentation=data.get('documentation')
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
        documentation=data.get('documentation')
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
    update = {}
    revision = credentialmanager.get_latest_credential_revision(
        id,
        _cred.revision
    )
    update['name'] = data.get('name', _cred.name)
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return jsonify({'error': 'Enabled must be a boolean.'}), 400
        update['enabled'] = data['enabled']
    else:
        update['enabled'] = _cred.enabled
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    services = servicemanager.get_services_for_credential(id)
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
        update['credential_pairs'] = json.dumps(credential_pairs)
    else:
        update['credential_pairs'] = _cred.decrypted_credential_pairs
    data_key = keymanager.create_datakey(encryption_context={'id': id})
    cipher = CipherManager(data_key['plaintext'], version=2)
    credential_pairs = cipher.encrypt(update['credential_pairs'])
    update['metadata'] = data.get('metadata', _cred.metadata)
    update['documentation'] = data.get('documentation', _cred.documentation)
    # Enforce documentation, EXCEPT if we are restoring an old revision
    if (not update['documentation'] and
            settings.get('ENFORCE_DOCUMENTATION') and
            not data.get('revision')):
        return jsonify({'error': 'documentation is a required field'}), 400
    # Try to save to the archive
    try:
        Credential(
            id='{0}-{1}'.format(id, revision),
            name=update['name'],
            data_type='archive-credential',
            credential_pairs=credential_pairs,
            metadata=update['metadata'],
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to add credential to archive.'}), 500
    try:
        cred = Credential(
            id=id,
            name=update['name'],
            data_type='credential',
            credential_pairs=credential_pairs,
            metadata=update['metadata'],
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        )
        cred.save()
    except PutError as e:
        logging.error(e)
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
        logging.warning(
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
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
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
        )
        cred.save()
    except PutError as e:
        logging.error(e)
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
    kms_client = clients.get_boto_client('kms')
    value = kms_client.generate_random(NumberOfBytes=128)['Plaintext']
    value = base64.urlsafe_b64encode(value).decode('UTF-8')
    value = re.sub(r'[\W_]+', '', value)
    if len(value) > VALUE_LENGTH:
        value = value[:VALUE_LENGTH]
    return jsonify({'value': value})
