import logging

from flask import jsonify
from flask import request
from pynamodb.exceptions import DoesNotExist, PutError

from confidant import authnz, settings
from confidant.app import app
from confidant.models.service import Service
from confidant.services import (
    credentialmanager,
    iamrolemanager,
    keymanager,
    servicemanager,
    webhook,
)
from confidant.utils import maintenance, misc
from confidant.utils.dynamodb import (
    decode_last_evaluated_key,
    encode_last_evaluated_key,
)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@app.route('/v1/roles', methods=['GET'])
@authnz.require_auth
def get_iam_roles_list():
    roles = iamrolemanager.get_iam_roles()
    return jsonify({'roles': roles})


@app.route('/v1/services', methods=['GET'])
@authnz.require_auth
def get_service_list():
    if not acl_module_check(resource_type='service',
                            actions='list'):
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
        action = 'metadata' if metadata_only else 'get'
        if not acl_module_check(resource_type='service',
                                action=action,
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
                                action='put',
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
