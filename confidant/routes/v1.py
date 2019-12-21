import json
import uuid
import logging
import base64
import re

from pynamodb.exceptions import PutError, DoesNotExist
from flask import request
from flask import jsonify

import confidant.clients
from confidant import authnz
from confidant import settings
from confidant.app import app
from confidant.services import graphite
from confidant.services import iamrolemanager
from confidant.services import keymanager
from confidant.services import webhook
from confidant.services import credentialmanager
from confidant.services import servicemanager
from confidant.services.ciphermanager import CipherManager
from confidant.utils import maintenance
from confidant.utils.dynamodb import (
    decode_last_evaluated_key,
    encode_last_evaluated_key,
)
from confidant.utils import misc
from confidant.models.credential import Credential
from confidant.models.blind_credential import BlindCredential
from confidant.models.service import Service


acl_module_check = misc.load_module(settings.ACL_MODULE)

VALUE_LENGTH = 50


@app.route('/v1/login', methods=['GET', 'POST'])
def login():
    '''
    Send user through login flow.
    '''
    return authnz.log_in()


@app.route('/v1/user/email', methods=['GET', 'POST'])
@authnz.require_auth
def get_user_info():
    '''
    Get the email address of the currently logged-in user.
    '''
    try:
        response = jsonify({'email': authnz.get_logged_in_user()})
    except authnz.UserUnknownError:
        response = jsonify({'email': None})
    return response


@app.route('/v1/client_config', methods=['GET'])
@authnz.require_auth
def get_client_config():
    '''
    Get configuration to help clients bootstrap themselves.
    '''
    # TODO: add more config in here.
    response = jsonify({
        'defined': settings.CLIENT_CONFIG,
        'generated': {
            'kms_auth_manage_grants': settings.KMS_AUTH_MANAGE_GRANTS,
            'aws_accounts': list(settings.SCOPED_AUTH_KEYS.values()),
            'xsrf_cookie_name': settings.XSRF_COOKIE_NAME,
            'maintenance_mode': settings.MAINTENANCE_MODE,
            'history_page_limit': settings.HISTORY_PAGE_LIMIT,
        }
    })
    return response


@app.route('/v1/services', methods=['GET'])
@authnz.require_auth
def get_service_list():
    if not acl_module_check(resource_type='service',
                            actions=['list']):
        msg = "{} does not have access to list services".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403
    services = []
    for service in Service.data_type_date_index.query('service'):
        services.append({
            'id': service.id,
            'account': service.account,
            'enabled': service.enabled,
            'revision': service.revision,
            'modified_date': service.modified_date,
            'modified_by': service.modified_by
        })
    services = sorted(services, key=lambda k: k['id'].lower())
    return jsonify({'services': services})


@app.route('/v1/roles', methods=['GET'])
@authnz.require_auth
def get_iam_roles_list():
    roles = iamrolemanager.get_iam_roles()
    return jsonify({'roles': roles})


@app.route('/v1/services/<id>', methods=['GET'])
@authnz.require_auth
def get_service(id):
    '''
    Get service metadata and all credentials for this service. This endpoint
    allows basic authentication.
    '''
    metadata_only = request.args.get('metadata_only', default=False, type=bool)
    if authnz.user_is_user_type('service'):
        if not authnz.user_is_service(id):
            logging.warning('Authz failed for service {0}.'.format(id))
            msg = 'Service is not authorized.'
            return jsonify({'error': msg}), 401
    else:
        logged_in_user = authnz.get_logged_in_user()
        acl_actions = ['metadata']
        if not metadata_only:
            acl_actions.append('get')
        if not acl_module_check(resource_type='service',
                                actions=acl_actions,
                                resource_id=id):
            msg = "{} does not have access to get service {}".format(
                authnz.get_logged_in_user(),
                id
            )
            error_msg = {'error': msg, 'reference': id}
            return jsonify(error_msg), 403

        logging.info(
            'get_service called on id={} by user={} metadata_only={}'.format(
                id,
                logged_in_user,
                metadata_only,
            )
        )
    try:
        service = Service.get(id)
        if not authnz.service_in_account(service.account):
            logging.warning(
                'Authz failed for service {0} (wrong account).'.format(id)
            )
            msg = 'Authenticated user is not authorized.'
            return jsonify({'error': msg}), 401
    except DoesNotExist:
        return jsonify({}), 404
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    logging.debug('Authz succeeded for service {0}.'.format(id))
    try:
        credentials = credentialmanager.get_credentials(
            service.credentials,
            metadata_only=metadata_only,
        )
    except KeyError:
        logging.exception('KeyError occurred in getting credentials')
        return jsonify({'error': 'Decryption error.'}), 500
    blind_credentials = credentialmanager.get_blind_credentials(
        service.blind_credentials,
        metadata_only=metadata_only,
    )
    return jsonify({
        'id': service.id,
        'account': service.account,
        'credentials': credentials,
        'blind_credentials': blind_credentials,
        'enabled': service.enabled,
        'revision': service.revision,
        'modified_date': service.modified_date,
        'modified_by': service.modified_by
    })


@app.route('/v1/archive/services/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_service_revisions(id):
    try:
        service = Service.get(id)
    except DoesNotExist:
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    revisions = []
    _range = range(1, service.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    for revision in Service.batch_get(ids):
        revisions.append({
            'id': revision.id,
            'account': revision.account,
            'revision': revision.revision,
            'enabled': revision.enabled,
            'credentials': list(revision.credentials),
            'blind_credentials': list(revision.blind_credentials),
            'modified_date': revision.modified_date,
            'modified_by': revision.modified_by
        })
    return jsonify({
        'revisions': sorted(
            revisions,
            key=lambda k: k['revision'],
            reverse=True
        )
    })


@app.route('/v1/archive/services', methods=['GET'])
@authnz.require_auth
def get_archive_service_list():
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
    services = []
    results = Service.data_type_date_index.query(
        'archive-service',
        scan_index_forward=False,
        limit=limit,
        last_evaluated_key=page,
    )
    for service in results:
        services.append({
            'id': service.id,
            'account': service.account,
            'revision': service.revision,
            'enabled': service.enabled,
            'credentials': list(service.credentials),
            'modified_date': service.modified_date,
            'modified_by': service.modified_by
        })
    service_list = {'services': services}
    service_list['next_page'] = encode_last_evaluated_key(
        results.last_evaluated_key
    )
    return jsonify(service_list)


@app.route('/v1/grants/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def ensure_grants(id):
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
        logging.error(msg)
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


@app.route('/v1/grants/<id>', methods=['GET'])
@authnz.require_auth
def get_grants(id):
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


@app.route('/v1/services/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def map_service_credentials(id):
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

    data = request.get_json()
    if data.get('credentials') or data.get('blind_credentials'):
        credentials = data.get('credentials', [])
        blind_credentials = data.get('blind_credentials', [])
        credentials = credentials + blind_credentials
        if not acl_module_check(resource_type='service',
                                actions=['update'],
                                resource_id=id,
                                kwargs={
                                    'credential_ids': credentials,
                                }):
            msg = "{} does not have access to map service credential {}".format(
                authnz.get_logged_in_user(),
                id
            )
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

    accounts = list(app.config['SCOPED_AUTH_KEYS'].values())
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
            logging.error(msg)
    # Try to save to the archive
    try:
        Service(
            id='{0}-{1}'.format(id, revision),
            data_type='archive-service',
            credentials=data.get('credentials'),
            blind_credentials=data.get('blind_credentials'),
            account=data.get('account'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user()
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to add service to archive.'}), 500

    try:
        service = Service(
            id=id,
            data_type='service',
            credentials=data.get('credentials'),
            blind_credentials=data.get('blind_credentials'),
            account=data.get('account'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user()
        )
        service.save()
    except PutError as e:
        logging.error(e)
        return jsonify({'error': 'Failed to update active service.'}), 500
    servicemanager.send_service_mapping_graphite_event(service, _service)
    webhook.send_event('service_update', [service.id], service.credentials)
    credentials = credentialmanager.get_credentials(
        service.credentials,
        metadata_only=True,
    )
    blind_credentials = credentialmanager.get_blind_credentials(
        service.blind_credentials,
        metadata_only=True,
    )
    return jsonify({
        'id': service.id,
        'account': service.account,
        'credentials': credentials,
        'blind_credentials': blind_credentials,
        'revision': service.revision,
        'enabled': service.enabled,
        'modified_date': service.modified_date,
        'modified_by': service.modified_by
    })


@app.route('/v1/services/<id>/<to_revision>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def revert_service_to_revision(id, to_revision):
    if not acl_module_check(resource_type='service',
                            actions=['revert'],
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
        logging.warning(
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
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if revert_service.data_type != 'archive-service':
        msg = 'id provided is not a service.'
        return jsonify({'error': msg}), 400
    if revert_service.equals(current_service):
        ret = {
            'error': 'No difference between old and new service.'
        }
        return jsonify(ret), 400
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
        logging.error(e)
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
        logging.error(e)
        return jsonify({'error': 'Failed to update active service.'}), 500
    servicemanager.send_service_mapping_graphite_event(service, current_service)
    webhook.send_event(
        'service_update',
        [service.id],
        service.credentials,
    )
    credentials = credentialmanager.get_credentials(
        service.credentials,
        metadata_only=True,
    )
    blind_credentials = credentialmanager.get_blind_credentials(
        service.blind_credentials,
        metadata_only=True,
    )
    return jsonify({
        'id': service.id,
        'account': service.account,
        'credentials': credentials,
        'blind_credentials': blind_credentials,
        'revision': service.revision,
        'enabled': service.enabled,
        'modified_date': service.modified_date,
        'modified_by': service.modified_by
    })


@app.route('/v1/credentials', methods=['GET'])
@authnz.require_auth
def get_credential_list():
    if not acl_module_check(resource_type='credential', actions=['list']):
        msg = "{} does not have access to list credentials".format(
            authnz.get_logged_in_user()
        )
        error_msg = {'error': msg}
        return jsonify(error_msg), 403

    credentials = []
    for cred in Credential.data_type_date_index.query('credential'):
        credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })

    credentials = sorted(credentials, key=lambda k: k['name'].lower())
    return jsonify({'credentials': credentials})


@app.route('/v1/credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_credential(id):
    if not acl_module_check(resource_type='credential',
                            actions=['metadata'],
                            resource_id=id):
        msg = "{} does not have access to credential {}".format(
            authnz.get_logged_in_user(),
            id
        )
        error_msg = {'error': msg, 'reference': id}
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
    services = []
    for service in Service.data_type_date_index.query('service'):
        services.append(service.id)

    credential = {
        'id': id,
        'name': cred.name,
        'credential_keys': cred.credential_keys,
        'metadata': cred.metadata,
        'services': services,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    }
    if acl_module_check(resource_type='credential',
                        actions=['get'],
                        resource_id=id):
        credential['credential_pairs'] = cred.decrypted_credential_pairs
        log_line = "{0} get credential {1}".format(
            authnz.get_logged_in_user(),
            id
        )
        logging.info(log_line)
    return jsonify(credential)


@app.route(
    '/v1/credentials/<id>/<old_revision>/<new_revision>',
    methods=['GET']
)
@authnz.require_auth
def diff_credential(id, old_revision, new_revision):
    if not acl_module_check(resource_type='credential',
                            actions=['metadata'],
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


@app.route('/v1/archive/credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_credential_revisions(id):
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
    revisions = []
    _range = range(1, cred.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    for revision in Credential.batch_get(ids):
        revisions.append({
            'id': revision.id,
            'name': revision.name,
            'metadata': cred.metadata,
            'revision': revision.revision,
            'enabled': revision.enabled,
            'modified_date': revision.modified_date,
            'modified_by': revision.modified_by,
            'documentation': revision.documentation
        })
    return jsonify({
        'revisions': sorted(
            revisions,
            key=lambda k: k['revision'],
            reverse=True
        )
    })


@app.route('/v1/archive/credentials', methods=['GET'])
@authnz.require_auth
def get_archive_credential_list():
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
    credentials = []
    results = Credential.data_type_date_index.query(
        'archive-credential',
        scan_index_forward=False,
        limit=limit,
        last_evaluated_key=page,
    )
    for cred in results:
        credentials.append({
            'id': cred.id,
            'name': cred.name,
            'metadata': cred.metadata,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    credential_list = {'credentials': credentials}
    credential_list['next_page'] = encode_last_evaluated_key(
        results.last_evaluated_key
    )
    return jsonify(credential_list)


@app.route('/v1/credentials', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def create_credential():
    if not acl_module_check(resource_type='credential', actions=['create']):
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
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': json.loads(cipher.decrypt(cred.credential_pairs)),
        'credential_keys': cred.credential_keys,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_credential_dependencies(id):
    services = servicemanager.get_services_for_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({
        'services': _services
    })


@app.route('/v1/credentials/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def update_credential(id):
    if not acl_module_check(resource_type='credential',
                            actions=['update'],
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
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': json.loads(cipher.decrypt(cred.credential_pairs)),
        'credential_keys': cred.credential_keys,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/credentials/<id>/<to_revision>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def revert_credential_to_revision(id, to_revision):
    if not acl_module_check(resource_type='credential',
                            actions=['revert'],
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
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/blind_credentials', methods=['GET'])
@authnz.require_auth
def get_blind_credential_list():
    blind_credentials = []
    for cred in BlindCredential.data_type_date_index.query('blind-credential'):
        blind_credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    return jsonify({'blind_credentials': blind_credentials})


@app.route('/v1/blind_credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_blind_credential(id):
    try:
        cred = BlindCredential.get(id)
    except DoesNotExist:
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    if (cred.data_type != 'blind-credential' and
            cred.data_type != 'archive-blind-credential'):
        return jsonify({}), 404
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/archive/blind_credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_blind_credential_revisions(id):
    try:
        cred = BlindCredential.get(id)
    except DoesNotExist:
        return jsonify({}), 404
    if (cred.data_type != 'blind-credential' and
            cred.data_type != 'archive-blind-credential'):
        logging.warning(
            'Item with id {0} does not exist.'.format(id)
        )
        return jsonify({}), 404
    revisions = []
    _range = range(1, cred.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(id, i))
    for revision in BlindCredential.batch_get(ids):
        revisions.append({
            'id': cred.id,
            'name': cred.name,
            'credential_pairs': cred.credential_pairs,
            'credential_keys': list(cred.credential_keys),
            'cipher_type': cred.cipher_type,
            'cipher_version': cred.cipher_version,
            'metadata': cred.metadata,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'data_key': cred.data_key,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    return jsonify({
        'revisions': sorted(
            revisions,
            key=lambda k: k['revision'],
            reverse=True
        )
    })


@app.route('/v1/archive/blind_credentials', methods=['GET'])
@authnz.require_auth
def get_archive_blind_credential_list():
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
    blind_credentials = []
    results = BlindCredential.data_type_date_index.query(
        'archive-blind-credential',
        scan_index_forward=False,
        limit=limit,
        last_evaluated_key=page,
    )
    for cred in results:
        blind_credentials.append({
            'id': cred.id,
            'name': cred.name,
            'credential_pairs': cred.credential_pairs,
            'credential_keys': list(cred.credential_keys),
            'cipher_type': cred.cipher_type,
            'cipher_version': cred.cipher_version,
            'metadata': cred.metadata,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'data_key': cred.data_key,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by,
            'documentation': cred.documentation
        })
    credential_list = {'blind_credentials': blind_credentials}
    credential_list['next_page'] = encode_last_evaluated_key(
        results.last_evaluated_key
    )
    return jsonify(credential_list)


@app.route('/v1/blind_credentials', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def create_blind_credential():
    data = request.get_json()
    missing = []
    required_args = ['cipher_version', 'cipher_type', 'credential_pairs',
                     'data_key']
    if settings.get('ENFORCE_DOCUMENTATION'):
        required_args.append('documentation')
    for arg in required_args:
        if not data.get(arg):
            missing.append(arg)
    if missing:
        return jsonify({
            'error': 'The following fields are required: {0}'.format(missing)
        }), 400
    if not isinstance(data['data_key'], dict):
        return jsonify({
            'error': 'data_key must be a dict with a region/key mapping.'
        }), 400
    if not isinstance(data.get('credential_keys', []), list):
        return jsonify({
            'error': 'credential_keys must be a list.'
        }), 400
    if not isinstance(data.get('metadata', {}), dict):
        return jsonify({'error': 'metadata must be a dict'}), 400
    for cred in BlindCredential.data_type_date_index.query(
            'blind-credential', name__eq=data['name']):
        # Conflict, the name already exists
        msg = 'Name already exists. See id: {0}'.format(cred.id)
        return jsonify({'error': msg, 'reference': cred.id}), 409
    # Generate an initial stable ID to allow name changes
    id = str(uuid.uuid4()).replace('-', '')
    # Try to save to the archive
    revision = 1
    BlindCredential(
        id='{0}-{1}'.format(id, revision),
        data_type='archive-blind-credential',
        name=data['name'],
        credential_pairs=data['credential_pairs'],
        credential_keys=data.get('credential_keys'),
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data['data_key'],
        cipher_type=data['cipher_type'],
        cipher_version=data['cipher_version'],
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation')
    ).save(id__null=True)
    # Make this the current revision
    cred = BlindCredential(
        id=id,
        data_type='blind-credential',
        name=data['name'],
        credential_pairs=data['credential_pairs'],
        credential_keys=data.get('credential_keys'),
        metadata=data.get('metadata'),
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data['data_key'],
        cipher_type=data['cipher_type'],
        cipher_version=data['cipher_version'],
        modified_by=authnz.get_logged_in_user(),
        documentation=data.get('documentation')
    )
    cred.save()
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/blind_credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_blind_credential_dependencies(id):
    services = servicemanager.get_services_for_blind_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({
        'services': _services
    })


@app.route('/v1/blind_credentials/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def update_blind_credential(id):
    try:
        _cred = BlindCredential.get(id)
    except DoesNotExist:
        return jsonify({'error': 'Blind credential not found.'}), 404
    if _cred.data_type != 'blind-credential':
        msg = 'id provided is not a blind-credential.'
        return jsonify({'error': msg}), 400
    data = request.get_json()
    update = {}
    revision = credentialmanager.get_latest_blind_credential_revision(
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
    services = servicemanager.get_services_for_blind_credential(id)
    if 'credential_pairs' in data:
        for key in ['data_key', 'cipher_type', 'cipher_version']:
            if key not in data:
                msg = '{0} required when updating credential_pairs.'
                msg = msg.format(key)
                return jsonify({'error': msg}), 400
        update['credential_pairs'] = data['credential_pairs']
        update['credential_keys'] = data.get('credential_keys', [])
        if not isinstance(update['credential_keys'], list):
            return jsonify({
                'error': 'credential_keys must be a list.'
            }), 400
        # Ensure credential keys don't conflicts with pairs from other
        # services
        conflicts = servicemanager.pair_key_conflicts_for_services(
            id,
            data['credential_keys'],
            services
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400
        if not isinstance(data['data_key'], dict):
            return jsonify({
                'error': 'data_key must be a dict with a region/key mapping.'
            }), 400
        update['data_key'] = data['data_key']
        update['cipher_type'] = data['cipher_type']
        update['cipher_version'] = data['cipher_version']
    else:
        update['credential_pairs'] = _cred.credential_pairs
        update['credential_keys'] = _cred.credential_keys
        update['data_key'] = _cred.data_key
        update['cipher_type'] = _cred.cipher_type
        update['cipher_version'] = _cred.cipher_version
    update['metadata'] = data.get('metadata', _cred.metadata)
    update['documentation'] = data.get('documentation', _cred.documentation)
    # Enforce documentation, EXCEPT if we are restoring an old revision
    if (not update['documentation'] and
            settings.get('ENFORCE_DOCUMENTATION') and
            not data.get('revision')):
        return jsonify({'error': 'documentation is a required field'}), 400
    # Try to save to the archive
    try:
        BlindCredential(
            id='{0}-{1}'.format(id, revision),
            data_type='archive-blind-credential',
            name=update['name'],
            credential_pairs=update['credential_pairs'],
            credential_keys=update['credential_keys'],
            metadata=update['metadata'],
            revision=revision,
            enabled=update['enabled'],
            data_key=update['data_key'],
            cipher_type=update['cipher_type'],
            cipher_version=update['cipher_version'],
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify(
            {'error': 'Failed to add blind-credential to archive.'}
        ), 500
    try:
        cred = BlindCredential(
            id=id,
            data_type='blind-credential',
            name=update['name'],
            credential_pairs=update['credential_pairs'],
            credential_keys=update['credential_keys'],
            metadata=update['metadata'],
            revision=revision,
            enabled=update['enabled'],
            data_key=update['data_key'],
            cipher_type=update['cipher_type'],
            cipher_version=update['cipher_version'],
            modified_by=authnz.get_logged_in_user(),
            documentation=update['documentation']
        )
        cred.save()
    except PutError as e:
        logging.error(e)
        return jsonify(
            {'error': 'Failed to update active blind-credential.'}
        ), 500
    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
        webhook.send_event('blind_credential_update', service_names, [cred.id])
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/blind_credentials/<id>/<to_revision>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
@maintenance.check_maintenance_mode
def revert_blind_credential_to_revision(id, to_revision):
    try:
        current_credential = BlindCredential.get(id)
    except DoesNotExist:
        return jsonify({'error': 'Blind credential not found.'}), 404
    if current_credential.data_type != 'blind-credential':
        msg = 'id provided is not a blind-credential.'
        return jsonify({'error': msg}), 400
    new_revision = credentialmanager.get_latest_blind_credential_revision(
        id,
        current_credential.revision
    )
    try:
        revert_credential = BlindCredential.get('{}-{}'.format(id, to_revision))
    except DoesNotExist:
        return jsonify({'error': 'Blind credential not found.'}), 404
    if revert_credential.data_type != 'archive-blind-credential':
        msg = 'id provided is not an archive-blind-credential.'
        return jsonify({'error': msg}), 400
    if revert_credential.equals(current_credential):
        ret = {
            'error': 'No difference between old and new blind credential.'
        }
        return jsonify(ret), 400
    services = servicemanager.get_services_for_blind_credential(id)
    if revert_credential.credential_keys:
        # Ensure credential keys don't conflicts with pairs from other
        # services
        conflicts = servicemanager.pair_key_conflicts_for_services(
            id,
            revert_credential.credential_keys,
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
        BlindCredential(
            id='{}-{}'.format(id, new_revision),
            data_type='archive-blind-credential',
            name=revert_credential.name,
            credential_pairs=revert_credential.credential_pairs,
            credential_keys=revert_credential.credential_keys,
            metadata=revert_credential.metadata,
            revision=new_revision,
            enabled=revert_credential.enabled,
            data_key=revert_credential.data_key,
            cipher_type=revert_credential.cipher_type,
            cipher_version=revert_credential.cipher_version,
            modified_by=authnz.get_logged_in_user(),
            documentation=revert_credential.documentation
        ).save(id__null=True)
    except PutError as e:
        logging.error(e)
        return jsonify(
            {'error': 'Failed to add blind-credential to archive.'}
        ), 500
    try:
        cred = BlindCredential(
            id=id,
            data_type='blind-credential',
            name=revert_credential.name,
            credential_pairs=revert_credential.credential_pairs,
            credential_keys=revert_credential.credential_keys,
            metadata=revert_credential.metadata,
            revision=new_revision,
            enabled=revert_credential.enabled,
            data_key=revert_credential.data_key,
            cipher_type=revert_credential.cipher_type,
            cipher_version=revert_credential.cipher_version,
            modified_by=authnz.get_logged_in_user(),
            documentation=revert_credential.documentation
        )
        cred.save()
    except PutError as e:
        logging.error(e)
        return jsonify(
            {'error': 'Failed to update active blind-credential.'}
        ), 500
    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
        webhook.send_event('blind_credential_update', service_names, [cred.id])
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': cred.credential_pairs,
        'credential_keys': list(cred.credential_keys),
        'cipher_type': cred.cipher_type,
        'cipher_version': cred.cipher_version,
        'metadata': cred.metadata,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'data_key': cred.data_key,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by,
        'documentation': cred.documentation
    })


@app.route('/v1/value_generator', methods=['GET'])
def generate_value():
    kms_client = confidant.clients.get_boto_client('kms')
    value = kms_client.generate_random(NumberOfBytes=128)['Plaintext']
    value = base64.urlsafe_b64encode(value).decode('UTF-8')
    value = re.sub(r'[\W_]+', '', value)
    if len(value) > VALUE_LENGTH:
        value = value[:VALUE_LENGTH]
    return jsonify({'value': value})
