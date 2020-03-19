import logging
import uuid

from flask import blueprints, jsonify, request
from pynamodb.exceptions import DoesNotExist, PutError

from confidant import authnz, settings
from confidant.services import (
    credentialmanager,
    graphite,
    webhook,
    servicemanager,
)
from confidant.utils import maintenance, misc
from confidant.utils.dynamodb import (
    decode_last_evaluated_key,
    encode_last_evaluated_key,
)
from confidant.models.blind_credential import BlindCredential

logger = logging.getLogger(__name__)
blueprint = blueprints.Blueprint('blind_credentials', __name__)

acl_module_check = misc.load_module(settings.ACL_MODULE)


@blueprint.route('/v1/blind_credentials', methods=['GET'])
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


@blueprint.route('/v1/blind_credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_blind_credential(id):
    try:
        cred = BlindCredential.get(id)
    except DoesNotExist:
        logger.warning(
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


@blueprint.route('/v1/archive/blind_credentials/<id>', methods=['GET'])
@authnz.require_auth
def get_archive_blind_credential_revisions(id):
    try:
        cred = BlindCredential.get(id)
    except DoesNotExist:
        return jsonify({}), 404
    if (cred.data_type != 'blind-credential' and
            cred.data_type != 'archive-blind-credential'):
        logger.warning(
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


@blueprint.route('/v1/archive/blind_credentials', methods=['GET'])
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
            logger.exception('Failed to parse provided page')
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


@blueprint.route('/v1/blind_credentials', methods=['POST'])
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


@blueprint.route('/v1/blind_credentials/<id>/services', methods=['GET'])
@authnz.require_auth
def get_blind_credential_dependencies(id):
    services = servicemanager.get_services_for_blind_credential(id)
    _services = [{'id': x.id, 'enabled': x.enabled} for x in services]
    return jsonify({
        'services': _services
    })


@blueprint.route('/v1/blind_credentials/<id>', methods=['PUT'])
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
        logger.error(e)
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
        logger.error(e)
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


@blueprint.route('/v1/blind_credentials/<id>/<to_revision>', methods=['PUT'])
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
        logger.error(e)
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
        logger.error(e)
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
