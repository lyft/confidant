import copy
import json

from pynamodb.exceptions import DoesNotExist

from confidant.app import app
from confidant.services import keymanager
from confidant.services.ciphermanager import CipherManager
from confidant.utils import stats
from confidant.models.credential import Credential
from confidant.models.blind_credential import BlindCredential


def get_credentials(credential_ids):
    credentials = []
    with stats.timer('service_batch_get_credentials'):
        for cred in Credential.batch_get(copy.deepcopy(credential_ids)):
            data_key = keymanager.decrypt_datakey(
                cred.data_key,
                encryption_context={'id': cred.id}
            )
            cipher_version = cred.cipher_version
            cipher = CipherManager(data_key, cipher_version)
            _credential_pairs = cipher.decrypt(cred.credential_pairs)
            _credential_pairs = json.loads(_credential_pairs)
            credentials.append({
                'id': cred.id,
                'data_type': 'credential',
                'name': cred.name,
                'enabled': cred.enabled,
                'revision': cred.revision,
                'credential_pairs': _credential_pairs,
                'metadata': cred.metadata,
                'documentation': cred.documentation
            })
    return credentials


def get_blind_credentials(credential_ids):
    credentials = []
    with stats.timer('service_batch_get_blind_credentials'):
        for cred in BlindCredential.batch_get(copy.deepcopy(credential_ids)):
            credentials.append({
                'id': cred.id,
                'data_type': 'blind-credential',
                'name': cred.name,
                'enabled': cred.enabled,
                'revision': cred.revision,
                'credential_pairs': cred.credential_pairs,
                'credential_keys': list(cred.credential_keys),
                'metadata': cred.metadata,
                'data_key': cred.data_key,
                'cipher_version': cred.cipher_version,
                'cipher_type': cred.cipher_type,
                'documentation': cred.documentation
            })
    return credentials


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
        if credential['data_type'] == 'credential':
            keys = credential['credential_pairs']
        elif credential['data_type'] == 'blind-credential':
            keys = credential['credential_keys']
        for key in keys:
            data = {
                'id': credential['id'],
                'data_type': credential['data_type']
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
