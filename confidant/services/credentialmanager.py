import copy
import re
import logging

from confidant import settings
from confidant.models.blind_credential import BlindCredential
from confidant.models.credential import Credential, CredentialArchive
from confidant.models.service import Service
from confidant.utils import stats
from pynamodb.exceptions import DoesNotExist


logger = logging.getLogger(__name__)


def get_credentials(credential_ids):
    with stats.timer('service_batch_get_credentials'):
        _credential_ids = copy.deepcopy(credential_ids)
        return [cred for cred in Credential.batch_get(_credential_ids)]


def get_blind_credentials(credential_ids, metadata_only=False):
    with stats.timer('service_batch_get_blind_credentials'):
        _credential_ids = copy.deepcopy(credential_ids)
        return [cred for cred in BlindCredential.batch_get(_credential_ids)]


def pair_key_conflicts_for_credentials(credential_ids, blind_credential_ids):
    conflicts = {}
    pair_keys = {}
    # If we don't care about conflicts, return immediately
    if settings.IGNORE_CONFLICTS:
        return conflicts
    # For all credentials, get their credential pairs and track which
    # credentials have which keys
    credentials = get_credentials(credential_ids)
    credentials.extend(get_blind_credentials(blind_credential_ids))
    for credential in credentials:
        for key in credential.credential_keys:
            data = {
                'id': credential.id,
                'data_type': credential.data_type
            }
            if key in pair_keys:
                pair_keys[key].append(data)
            else:
                pair_keys[key] = [data]
    # Iterate the credential pair keys, if there's any keys with more than
    # one credential add it to the conflict dict.
    for key, data in pair_keys.items():
        if len(data) > 1:
            blind_ids = [k['id'] for k in data
                         if k['data_type'] == 'blind-credential']
            ids = [k['id'] for k in data if k['data_type'] == 'credential']
            conflicts[key] = {
                'credentials': ids,
                'blind_credentials': blind_ids
            }
    return conflicts


def check_credential_pair_values(credential_pairs):
    for key, val in credential_pairs.items():
        if isinstance(val, dict) or isinstance(val, list):
            ret = {'error': 'credential pairs must be key: value'}
            return (False, ret)
        if re.search(r'\s', key):
            ret = {'error': 'credential key must not contain whitespace'}
            return (False, ret)
    return (True, {})


def lowercase_credential_pairs(credential_pairs):
    return {i.lower(): j for i, j in credential_pairs.items()}


def get_revision_ids_for_credential(credential):
    """
    For the given credential, return a list of archive credential IDs.
    """
    _range = range(1, credential.revision + 1)
    ids = []
    for i in _range:
        ids.append("{0}-{1}".format(credential.id, i))
    return ids


def get_latest_credential_revision(id, revision):
    i = revision + 1
    while True:
        _id = '{0}-{1}'.format(id, i)
        try:
            Credential.get(_id)
        except DoesNotExist:
            return i
        i = i + 1


def get_latest_blind_credential_revision(id, revision):
    i = revision + 1
    while True:
        _id = '{0}-{1}'.format(id, i)
        try:
            BlindCredential.get(_id)
        except DoesNotExist:
            return i
        i = i + 1


def _delete_credentials(credentials, force=False):
    _deletes = ', '.join([credential.id for credential in credentials])
    if not force:
        logger.info(
            'Would have deleted credential and revisions: {}'.format(
                _deletes,
            )
        )
        return
    logger.info(
        'Deleting credential and revisions: {}'.format(
            _deletes,
        )
    )
    with Credential.batch_write() as batch:
        for delete in credentials:
            batch.delete(delete)
    stats.incr('archive.delete.success')


def _credential_in_service(_id, services):
    for service in services:
        if _id in service.credentials:
            return True
    return False


def _save_credentials_to_archive(credentials_to_save, force=False):
    _saves = ', '.join([credential.id for credential in credentials_to_save])
    if not force:
        logger.info(
            'Would have archived credential and revisions: {}'.format(
                _saves,
            )
        )
        return
    logger.info(
        'Archiving credential and revisions: {}'.format(
            _saves,
        )
    )
    with CredentialArchive.batch_write() as batch:
        for credential in credentials_to_save:
            batch.save(credential)
    stats.incr('archive.save.success')


def archive_credentials(credentials, force):
    if not settings.DYNAMODB_TABLE_ARCHIVE:
        raise DoesNotExist('DYNAMODB_TABLE_ARCHIVE is not configured, exiting.')

    failed = {}
    services = list(Service.data_type_date_index.query('service'))
    for credential in credentials:
        if credential.enabled:
            logger.warning('Not archiving enabled '
                           'credential {}'.format(credential.id))
            failed[credential.id] = 'Credential still enabled'
            continue
        if _credential_in_service(credential.id, services):
            msg = ('Skipping archival of disabled credential {}, as it'
                   ' is still mapped to a service.').format(credential.id)
            logger.warning(msg)
            failed[credential.id] = 'Credential has mapped services'
            continue
        saves = []
        deletes = []
        # save the current record.
        archive_credential = CredentialArchive.from_credential(
            credential,
        )
        saves.append(archive_credential)
        # fetch and save every revision
        revisions = Credential.batch_get(
            get_revision_ids_for_credential(credential)
        )
        for revision in revisions:
            archive_revision = CredentialArchive.from_credential(
                revision,
            )
            saves.append(archive_revision)
            deletes.append(revision)
        deletes.append(credential)
        try:
            _save_credentials_to_archive(saves, force=force)
        except Exception:
            logger.exception(
                'Failed to batch save {}, skipping deletion.'.format(
                    credential.id
                )
            )
            failed[credential.id] = 'Archive failed'
            stats.incr('archive.save.failure')
            continue
        try:
            _delete_credentials(deletes, force=force)
        except Exception:
            logger.exception(
                'Failed to batch delete {}'.format(credential.id)
            )
            failed[credential.id] = 'Delete failed'
            stats.incr('archive.delete.failure')
    return failed
