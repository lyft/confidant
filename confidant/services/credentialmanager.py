import copy

from pynamodb.exceptions import DoesNotExist

from confidant.app import app
from confidant.utils import stats
from confidant.models.credential import Credential
from confidant.models.blind_credential import BlindCredential


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
    if app.config['IGNORE_CONFLICTS']:
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
    return (True, {})


def lowercase_credential_pairs(credential_pairs):
    return {i.lower(): j for i, j in credential_pairs.items()}


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
