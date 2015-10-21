from confidant import app
from confidant import iam
from confidant import log
from confidant import keymanager
from confidant import authnz
from confidant import stats
from confidant import graphite
from confidant.ciphermanager import CipherManager
from confidant.models.credential import Credential
from confidant.models.service import Service
from pynamodb.exceptions import PutError
from flask import request
from flask import jsonify
from botocore.exceptions import ClientError

import json
import uuid
import copy


@app.route('/v1/user/email', methods=['GET', 'POST'])
@authnz.require_auth
def get_user_info():
    '''
    Get the email address of the currently logged-in user.
    '''
    response = jsonify({'email': authnz.get_logged_in_user_email()})
    response.set_cookie('XSRF-TOKEN', authnz.get_csrf_token())
    return response


@app.route('/v1/services', methods=['GET'])
@authnz.require_auth
def get_service_list():
    services = []
    for service in Service.data_type_date_index.query('service'):
        services.append({
            'id': service.id,
            'enabled': service.enabled,
            'revision': service.revision,
            'modified_date': service.modified_date,
            'modified_by': service.modified_by
        })
    return jsonify({'services': services})


@app.route('/v1/profiles', methods=['GET'])
@authnz.require_auth
def get_iam_profile_list():
    try:
        profiles = [x.name for x in iam.instance_profiles.all()]
    except ClientError:
        return jsonify({'error': 'Unable to fetch iam profiles.'}), 500
    return jsonify({'profiles': profiles})


@app.route('/v1/services/<id>', methods=['GET'])
@authnz.require_auth
def get_service(id):
    '''
    Get service metadata and all credentials for this service. This endpoint
    allows basic authentication.
    '''
    if authnz.user_in_role('service') and not authnz.user_is_service(id):
        log.warning('Authz failed for service {0}.'.format(id))
        msg = 'Authenticated user is not authorized.'
        return jsonify({'error': msg}), 401
    log.debug('Authz succeeded for service {0}.'.format(id))
    try:
        service = Service.get(id)
    except Service.DoesNotExist:
        return jsonify({}), 404
    if (service.data_type != 'service' and
            service.data_type != 'archive-service'):
        return jsonify({}), 404
    try:
        credentials = _get_credentials(service.credentials)
    except KeyError:
        return jsonify({'error': 'Decryption error.'}), 500
    return jsonify({
        'id': service.id,
        'credentials': credentials,
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
    except Service.DoesNotExist:
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
            'revision': revision.revision,
            'enabled': revision.enabled,
            'credentials': list(revision.credentials),
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
    services = []
    for service in Service.data_type_date_index.query(
            'archive-service', scan_index_forward=False):
        services.append({
            'id': service.id,
            'revision': service.revision,
            'enabled': service.enabled,
            'credentials': list(service.credentials),
            'modified_date': service.modified_date,
            'modified_by': service.modified_by
        })
    return jsonify({'services': services})


@app.route('/v1/grants/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
def ensure_grants(id):
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
    except Service.DoesNotExist:
        msg = 'id provided does not exist.'
        return jsonify({'error': msg}), 400
    try:
        keymanager.ensure_grants(id)
    except keymanager.ServiceCreateGrantError:
        msg = 'Failed to add grants for service.'
        log.error(msg)
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
    except Service.DoesNotExist:
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
def map_service_credentials(id):
    data = request.get_json()
    try:
        _service = Service.get(id)
        if _service.data_type != 'service':
            msg = 'id provided is not a service.'
            return jsonify({'error': msg}), 400
        revision = _service.revision + 1
        _service_credential_ids = _service.credentials
    except Service.DoesNotExist:
        revision = 1
        _service_credential_ids = []

    if data.get('credentials'):
        conflicts = _pair_key_conflicts_for_credentials(
            copy.deepcopy(data['credentials'])
        )
        if conflicts:
            ret = {
                'error': 'Conflicting key pairs in mapped service.',
                'conflicts': conflicts
            }
            return jsonify(ret), 400

    # If this is the first revision, we should attempt to create a grant for
    # this service.
    if revision == 1:
        try:
            keymanager.ensure_grants(id)
        except keymanager.ServiceCreateGrantError:
            msg = 'Failed to add grants for {0}.'.format(id)
            log.error(msg)
    # Try to save to the archive
    try:
        Service(
            id='{0}-{1}'.format(id, revision),
            data_type='archive-service',
            credentials=data.get('credentials'),
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user_email()
        ).save(id__null=True)
    except PutError as e:
        log.error(e)
        return jsonify({'error': 'Failed to add service to archive.'}), 500

    try:
        service = Service(
            id=id,
            data_type='service',
            credentials=data['credentials'],
            enabled=data.get('enabled'),
            revision=revision,
            modified_by=authnz.get_logged_in_user_email()
        )
        service.save()
    except PutError as e:
        log.error(e)
        return jsonify({'error': 'Failed to update active service.'}), 500
    added = list(set(service.credentials) - set(_service_credential_ids))
    removed = list(set(_service_credential_ids) - set(service.credentials))
    msg = 'Added credentials: {0}; Removed credentials {1}; Revision {2}'
    msg = msg.format(added, removed, service.revision)
    graphite.send_event([id], msg)
    try:
        credentials = _get_credentials(service.credentials)
    except KeyError:
        return jsonify({'error': 'Decryption error.'}), 500
    return jsonify({
        'id': service.id,
        'credentials': credentials,
        'revision': service.revision,
        'enabled': service.enabled,
        'modified_date': service.modified_date,
        'modified_by': service.modified_by
    })


@app.route('/v1/credentials', methods=['GET'])
@authnz.require_auth
def get_credential_list():
    credentials = []
    for cred in Credential.data_type_date_index.query('credential'):
        credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by
        })
    return jsonify({'credentials': credentials})


@app.route('/v1/credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_credential(id):
    try:
        cred = Credential.get(id)
    except Credential.DoesNotExist:
        return jsonify({}), 404
    if (cred.data_type != 'credential' and
            cred.data_type != 'archive-credential'):
        return jsonify({}), 404
    services = []
    for service in Service.data_type_date_index.query('service'):
        services.append(service.id)
    if cred.data_type == 'credential':
        context = id
    else:
        context = id.split('-')[0]
    data_key = keymanager.decrypt_key(
        cred.data_key,
        encryption_context={'id': context}
    )
    cipher_version = cred.cipher_version
    cipher = CipherManager(data_key, cipher_version)
    _credential_pairs = cipher.decrypt(cred.credential_pairs)
    _credential_pairs = json.loads(_credential_pairs)
    return jsonify({
        'id': id,
        'name': cred.name,
        'credential_pairs': _credential_pairs,
        'services': services,
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by
    })


@app.route('/v1/archive/credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_credential_revisions(id):
    try:
        cred = Credential.get(id)
    except Credential.DoesNotExist:
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
            'revision': revision.revision,
            'enabled': revision.enabled,
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


@app.route('/v1/archive/credentials', methods=['GET'])
@authnz.require_auth
def get_archive_credential_list():
    credentials = []
    for cred in Credential.data_type_date_index.query(
            'archive-credential', scan_index_forward=False):
        credentials.append({
            'id': cred.id,
            'name': cred.name,
            'revision': cred.revision,
            'enabled': cred.enabled,
            'modified_date': cred.modified_date,
            'modified_by': cred.modified_by
        })
    return jsonify({'credentials': credentials})


def _get_credentials(credential_ids):
    credentials = []
    with stats.timer('service_batch_get_credentials'):
        for cred in Credential.batch_get(credential_ids):
            data_key = keymanager.decrypt_key(
                cred.data_key,
                encryption_context={'id': cred.id}
            )
            cipher_version = cred.cipher_version
            cipher = CipherManager(data_key, cipher_version)
            _credential_pairs = cipher.decrypt(cred.credential_pairs)
            _credential_pairs = json.loads(_credential_pairs)
            credentials.append({
                'id': cred.id,
                'name': cred.name,
                'enabled': cred.enabled,
                'revision': cred.revision,
                'credential_pairs': _credential_pairs
            })
    return credentials


def _pair_key_conflicts_for_credentials(credential_ids):
    conflicts = {}
    pair_keys = {}
    # For all credentials, get their credential pairs and track which
    # credentials have which keys
    credentials = _get_credentials(credential_ids)
    for credential in credentials:
        for key in credential['credential_pairs']:
            if key in pair_keys:
                pair_keys[key].append(credential['id'])
            else:
                pair_keys[key] = [credential['id']]
    # Iterate the credential pair keys, if there's any keys with more than
    # one credential add it to the conflict dict.
    for key, ids in pair_keys.iteritems():
        if len(ids) > 1:
            conflicts[key] = {'credentials': ids}
    return conflicts


def _get_services_for_credential(_id):
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.credentials:
            services.append(service)
    return services


def _check_credential_pair_uniqueness(
        credential_pairs, _id=None, services=None
        ):
    for key, val in credential_pairs.iteritems():
        if isinstance(val, dict) or isinstance(val, list):
            ret = {'error': 'credential pairs must be key: value'}
            return (False, ret)
    return (True, {})


def _pair_key_conflicts_for_services(_id, credential_pairs, services):
    conflicts = {}
    service_map = {}
    # Find all other credentials mapped against any service this credential
    # is mapped with.
    for service in services:
        for credential in service.credentials:
            if credential in service_map:
                service_map[credential].append(service.id)
            else:
                service_map[credential] = [service.id]
    credential_ids = service_map.keys()
    if _id in credential_ids:
        credential_ids.remove(_id)
    credentials = _get_credentials(credential_ids)
    pair_keys = credential_pairs.keys()
    for credential in credentials:
        services = service_map[credential['id']]
        for key in pair_keys:
            if key in credential['credential_pairs']:
                if key not in conflicts:
                    conflicts[key] = {
                        'credentials': [credential['id']],
                        'services': services
                    }
                else:
                    conflicts[key]['services'].extend(services)
                    conflicts[key]['credentials'].append(credential['id'])
                conflicts[key]['services'] = list(
                    set(conflicts[key]['services'])
                )
                conflicts[key]['credentials'] = list(
                    set(conflicts[key]['credentials'])
                )
    return conflicts


def _lowercase_credential_pairs(credential_pairs):
    return {i.lower(): j for i, j in credential_pairs.iteritems()}


@app.route('/v1/credentials', methods=['POST'])
@authnz.require_auth
@authnz.require_csrf_token
def create_credential():
    data = request.get_json()
    if not data.get('credential_pairs'):
        return jsonify({'error': 'credential_pairs is a required field'}), 400
    # Ensure credential pair keys are lowercase
    credential_pairs = _lowercase_credential_pairs(data['credential_pairs'])
    if not _check_credential_pair_uniqueness(credential_pairs):
        ret = {'error': 'credential pairs must be key: value'}
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
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by=authnz.get_logged_in_user_email()
    ).save(id__null=True)
    # Make this the current revision
    cred = Credential(
        id=id,
        data_type='credential',
        name=data['name'],
        credential_pairs=credential_pairs,
        revision=revision,
        enabled=data.get('enabled'),
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by=authnz.get_logged_in_user_email()
    )
    cred.save()
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': json.loads(cipher.decrypt(cred.credential_pairs)),
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by
    })


@app.route('/v1/credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_credential_dependencies(id):
    services = _get_services_for_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({
        'services': _services
    })


@app.route('/v1/credentials/<id>', methods=['PUT'])
@authnz.require_auth
@authnz.require_csrf_token
def update_credential(id):
    try:
        _cred = Credential.get(id)
    except Credential.DoesNotExist:
        return jsonify({'error': 'Credential not found.'}), 404
    if _cred.data_type != 'credential':
        msg = 'id provided is not a credential.'
        return jsonify({'error': msg}), 400
    data = request.get_json()
    update = {}
    revision = _cred.revision + 1
    update['name'] = data.get('name', _cred.name)
    if 'enabled' in data:
        if not isinstance(data['enabled'], bool):
            return jsonify({'error': 'Enabled must be a boolean.'}), 400
        update['enabled'] = data['enabled']
    else:
        update['enabled'] = _cred.enabled
    services = _get_services_for_credential(id)
    if 'credential_pairs' in data:
        # Ensure credential pair keys are lowercase
        credential_pairs = _lowercase_credential_pairs(
            data['credential_pairs']
        )
        if not _check_credential_pair_uniqueness(credential_pairs):
            ret = {'error': 'credential pairs must be key: value'}
            return jsonify(ret), 400
        # Ensure credential pairs don't conflicts with pairs from other
        # services
        conflicts = _pair_key_conflicts_for_services(
            id,
            credential_pairs,
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
        data_key = keymanager.decrypt_key(
            _cred.data_key,
            encryption_context={'id': id}
        )
        cipher_version = _cred.cipher_version
        cipher = CipherManager(data_key, cipher_version)
        update['credential_pairs'] = cipher.decrypt(_cred.credential_pairs)
    data_key = keymanager.create_datakey(encryption_context={'id': id})
    cipher = CipherManager(data_key['plaintext'], version=2)
    credential_pairs = cipher.encrypt(update['credential_pairs'])
    # Try to save to the archive
    try:
        Credential(
            id='{0}-{1}'.format(id, revision),
            name=update['name'],
            data_type='archive-credential',
            credential_pairs=credential_pairs,
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user_email()
        ).save(id__null=True)
    except PutError as e:
        log.error(e)
        return jsonify({'error': 'Failed to add credential to archive.'}), 500
    try:
        cred = Credential(
            id=id,
            name=update['name'],
            data_type='credential',
            credential_pairs=credential_pairs,
            enabled=update['enabled'],
            revision=revision,
            data_key=data_key['ciphertext'],
            cipher_version=2,
            modified_by=authnz.get_logged_in_user_email()
        )
        cred.save()
    except PutError as e:
        log.error(e)
        return jsonify({'error': 'Failed to update active credential.'}), 500
    if services:
        service_names = [x.id for x in services]
        msg = 'Updated credential "{0}" ({1}); Revision {2}'
        msg = msg.format(cred.name, cred.id, cred.revision)
        graphite.send_event(service_names, msg)
    return jsonify({
        'id': cred.id,
        'name': cred.name,
        'credential_pairs': json.loads(cipher.decrypt(cred.credential_pairs)),
        'revision': cred.revision,
        'enabled': cred.enabled,
        'modified_date': cred.modified_date,
        'modified_by': cred.modified_by
    })
