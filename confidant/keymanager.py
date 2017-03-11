import base64
import hashlib
import datetime
import json
import logging
import botocore

from botocore.exceptions import ClientError
from lru import LRU

import confidant.services
from confidant.app import app
from confidant.utils import stats
from confidant.lib import cryptolib

config = botocore.config.Config(
    connect_timeout=app.config['KMS_CONNECTION_TIMEOUT'],
    read_timeout=app.config['KMS_READ_TIMEOUT'],
    max_pool_connections=app.config['KMS_MAX_POOL_CONNECTIONS']
)
auth_kms_client = confidant.services.get_boto_client(
    'kms',
    config={'name': 'keymanager', 'config': config}
)
at_rest_kms_client = confidant.services.get_boto_client(
    'kms',
    config={'name': 'keymanager', 'config': config}
)
iam_resource = confidant.services.get_boto_resource('iam')

DATAKEYS = {}
SERVICEKEYS = {}
TOKENS = LRU(app.config['KMS_AUTH_TOKEN_CACHE_SIZE'])
KEY_METADATA = {}


def get_key_arn(key_alias):
    if key_alias not in KEY_METADATA:
        KEY_METADATA[key_alias] = auth_kms_client.describe_key(
            KeyId='alias/{0}'.format(key_alias)
        )
    return KEY_METADATA[key_alias]['KeyMetadata']['Arn']


def get_key_id(key_alias):
    if key_alias not in KEY_METADATA:
        KEY_METADATA[key_alias] = auth_kms_client.describe_key(
            KeyId='alias/{0}'.format(key_alias)
        )
    return KEY_METADATA[key_alias]['KeyMetadata']['KeyId']


def get_key_alias_from_cache(key_arn):
    '''
    Find a key's alias by looking up its key_arn in the KEY_METADATA
    cache. This function will only work after a key has been lookedup by its
    alias and is meant as a convenience function for turning an ARN that's
    already been looked up back into its alias.
    '''
    for alias in KEY_METADATA:
        if KEY_METADATA[alias]['KeyMetadata']['Arn'] == key_arn:
            return alias
    return None


def create_datakey(encryption_context):
    '''
    Create a datakey from KMS.
    '''
    # Disabled encryption is dangerous, so we don't use falsiness here.
    if app.config['USE_ENCRYPTION'] is False:
        logging.warning('Creating a mock datakey in keymanager.create_datakey.'
                        ' If you are not running in a development or test'
                        ' environment, this should not be happening!')
        return cryptolib.create_mock_datakey()
    # underlying lib does generate random and encrypt, so increment by 2
    stats.incr('at_rest_action', 2)
    return cryptolib.create_datakey(
        encryption_context,
        'alias/{0}'.format(app.config.get('KMS_MASTER_KEY')),
        client=at_rest_kms_client
    )


def decrypt_datakey(data_key, encryption_context=None):
    '''
    Decrypt a datakey.
    '''
    # Disabled encryption is dangerous, so we don't use falsiness here.
    if app.config['USE_ENCRYPTION'] is False:
        logging.warning('Decypting a mock data key in'
                        ' keymanager.decrypt_datakey. If you are not running'
                        ' in a development or test environment, this should'
                        ' not be happening!')
        return cryptolib.decrypt_mock_datakey(data_key)
    sha = hashlib.sha256(data_key).hexdigest()
    if sha not in DATAKEYS:
        stats.incr('at_rest_action')
        plaintext = cryptolib.decrypt_datakey(
            data_key,
            encryption_context,
            client=at_rest_kms_client
        )
        DATAKEYS[sha] = plaintext
    return DATAKEYS[sha]


def valid_service_auth_key(key_arn):
    if key_arn == get_key_arn(app.config['AUTH_KEY']):
        return True
    for key in app.config['SCOPED_AUTH_KEYS']:
        if key_arn == get_key_arn(key):
            return True
    return False


def decrypt_token(version, user_type, _from, token):
    '''
    Decrypt a token.
    '''
    if (version > app.config['KMS_MAXIMUM_TOKEN_VERSION'] or
            version < app.config['KMS_MINIMUM_TOKEN_VERSION']):
        raise TokenDecryptionError('Unacceptable token version.')
    stats.incr('token_version_{0}'.format(version))
    try:
        token_key = '{0}{1}'.format(
            hashlib.sha256(token).hexdigest(),
            _from
        )
    except Exception:
        raise TokenDecryptionError('Authentication error.')
    if token_key not in TOKENS:
        try:
            token = base64.b64decode(token)
            context = {
                # This key is sent to us.
                'to': app.config['AUTH_CONTEXT'],
                # From a service.
                'from': _from
            }
            if version > 1:
                context['user_type'] = user_type
            with stats.timer('kms_decrypt_token'):
                data = auth_kms_client.decrypt(
                    CiphertextBlob=token,
                    EncryptionContext=context
                )
            # Decrypt doesn't take KeyId as an argument. We need to verify the
            # correct key was used to do the decryption.
            # Annoyingly, the KeyId from the data is actually an arn.
            key_arn = data['KeyId']
            if user_type == 'service':
                if not valid_service_auth_key(key_arn):
                    raise TokenDecryptionError(
                        'Authentication error (wrong KMS key).'
                    )
            elif user_type == 'user':
                if key_arn != get_key_arn(app.config['USER_AUTH_KEY']):
                    raise TokenDecryptionError(
                        'Authentication error (wrong KMS key).'
                    )
            else:
                raise TokenDecryptionError(
                    'Authentication error. Unsupported user_type.'
                )
            plaintext = data['Plaintext']
            payload = json.loads(plaintext)
            key_alias = get_key_alias_from_cache(key_arn)
            ret = {'payload': payload, 'key_alias': key_alias}
        except TokenDecryptionError:
            raise
        # We don't care what exception is thrown. For paranoia's sake, fail
        # here.
        except Exception:
            logging.exception('Failed to validate token.')
            raise TokenDecryptionError('Authentication error. General error.')
    else:
        ret = TOKENS[token_key]
    time_format = "%Y%m%dT%H%M%SZ"
    now = datetime.datetime.utcnow()
    try:
        not_before = datetime.datetime.strptime(
            ret['payload']['not_before'],
            time_format
        )
        not_after = datetime.datetime.strptime(
            ret['payload']['not_after'],
            time_format
        )
    except Exception:
        logging.exception(
            'Failed to get not_before and not_after from token payload.'
        )
        raise TokenDecryptionError('Authentication error. Missing validity.')
    delta = (not_after - not_before).seconds / 60
    if delta > app.config['AUTH_TOKEN_MAX_LIFETIME']:
        logging.warning('Token used which exceeds max token lifetime.')
        raise TokenDecryptionError(
            'Authentication error. Token lifetime exceeded.'
        )
    if (now < not_before) or (now > not_after):
        logging.warning('Invalid time validity for token.')
        raise TokenDecryptionError(
            'Authentication error. Invalid time validity for token.'
        )
    TOKENS[token_key] = ret
    return TOKENS[token_key]


def get_grants():
    _grants = []
    next_marker = None
    while True:
        if next_marker:
            grants = auth_kms_client.list_grants(
                KeyId=get_key_id(app.config['AUTH_KEY']),
                Marker=next_marker,
                Limit=250
            )
        else:
            grants = auth_kms_client.list_grants(
                KeyId=get_key_id(app.config['AUTH_KEY'])
            )
        for grant in grants['Grants']:
            _grants.append(grant)
        if 'NextMarker' not in grants:
            break
        else:
            next_marker = grants['NextMarker']
    return _grants


def ensure_grants(service_name):
    '''
    Add encryption and decryption grants for the service.

    TODO: We should probably orchestrate this, rather than doing it in
          confidant.
    '''
    if not app.config['KMS_AUTH_MANAGE_GRANTS']:
        return
    try:
        role = iam_resource.Role(name=service_name)
        role.load()
        grants = get_grants()
        _ensure_grants(role, grants)
    except ClientError:
        logging.exception(
            'Failed to ensure grants for {0}.'.format(service_name)
        )
        raise ServiceCreateGrantError()


def grants_exist(service_name):
    try:
        role = iam_resource.Role(name=service_name)
        role.load()
    except ClientError:
        return {
            'encrypt_grant': False,
            'decrypt_grant': False
        }
    try:
        grants = get_grants()
        encrypt_grant, decrypt_grant = _grants_exist(role, grants)
    except ClientError:
        logging.exception('Failed to get grants for {0}.'.format(service_name))
        raise ServiceGetGrantError()
    return {
        'encrypt_grant': encrypt_grant,
        'decrypt_grant': decrypt_grant
    }


def _grants_exist(role, grants):
    encrypt_constraint = {
        'EncryptionContextSubset': {
            'from': role.role_name
        }
    }
    if app.config['KMS_MINIMUM_TOKEN_VERSION'] > 1:
        # For newer token versions we require role to be a part of the
        # encryption context, so that we can limit service auth to services.
        encrypt_constraint['EncryptionContextSubset']['user_type'] = 'service'
    decrypt_constraint = {
        'EncryptionContextSubset': {
            'to': role.role_name
        }
    }
    encrypt_grant = False
    decrypt_grant = False
    for grant in grants:
        if role.arn == grant['GranteePrincipal']:
            if ('Encrypt' in grant['Operations'] and
                    grant['Constraints'] == encrypt_constraint):
                encrypt_grant = True
            elif ('Decrypt' in grant['Operations'] and
                    grant['Constraints'] == decrypt_constraint):
                decrypt_grant = True
    return (encrypt_grant, decrypt_grant)


def _ensure_grants(role, grants):
    encrypt_constraint = {
        'EncryptionContextSubset': {
            'from': role.role_name
        }
    }
    if app.config['KMS_MINIMUM_TOKEN_VERSION'] > 1:
        # For newer token versions we require role to be a part of the
        # encryption context, so that we can limit service auth to services.
        encrypt_constraint['EncryptionContextSubset']['user_type'] = 'service'
    decrypt_constraint = {
        'EncryptionContextSubset': {
            'to': role.role_name
        }
    }
    encrypt_grant, decrypt_grant = _grants_exist(role, grants)
    if not encrypt_grant:
        logging.info('Creating encrypt grant for {0}'.format(role.arn))
        auth_kms_client.create_grant(
            KeyId=get_key_id(app.config['AUTH_KEY']),
            GranteePrincipal=role.arn,
            Operations=['Encrypt', 'Decrypt'],
            Constraints=encrypt_constraint
        )
    if not decrypt_grant:
        logging.info('Creating decrypt grant for {0}'.format(role.arn))
        auth_kms_client.create_grant(
            KeyId=get_key_id(app.config['AUTH_KEY']),
            GranteePrincipal=role.arn,
            Operations=['Decrypt'],
            Constraints=decrypt_constraint
        )


class ServiceGetGrantError(Exception):
    pass


class ServiceCreateGrantError(Exception):
    pass


class TokenDecryptionError(Exception):
    pass
