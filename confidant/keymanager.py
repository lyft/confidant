import base64
import hashlib
import datetime
import json
from botocore.exceptions import ClientError
from cryptography.fernet import Fernet

from confidant import app
from confidant import kms
from confidant import iam
from confidant import stats
from confidant import lru
from confidant import log

DATAKEYS = {}
SERVICEKEYS = {}
TOKENS = lru.LRUCache(4096)
KEY_METADATA = {}


def get_key_arn(key_alias):
    if key_alias not in KEY_METADATA:
        KEY_METADATA[key_alias] = kms.describe_key(
            KeyId='alias/{0}'.format(key_alias)
        )
    return KEY_METADATA[key_alias]['KeyMetadata']['Arn']


def get_key_id(key_alias):
    if key_alias not in KEY_METADATA:
        KEY_METADATA[key_alias] = kms.describe_key(
            KeyId='alias/{0}'.format(key_alias)
        )
    return KEY_METADATA[key_alias]['KeyMetadata']['KeyId']


def _create_mock_datakey():
    '''
    Mock encryption meant to be used for testing or development. Returns a
    generated data key, but the encrypted version of the key is simply the
    unencrypted version. If this is called for anything other than testing
    or development purposes, it will cause unencrypted keys to be stored along
    with the encrypted content, rending the encryption worthless.
    '''
    key = Fernet.generate_key()
    return {'ciphertext': key,
            'plaintext': key}


def create_datakey(encryption_context):
    '''
    Create a datakey from KMS.
    '''
    # Disabled encryption is dangerous, so we don't use falsiness here.
    if app.config['USE_ENCRYPTION'] is False:
        log.warning('Creating a mock data key in keymanager.create_datakey.'
                    ' If you are not running in a development or test'
                    ' environment, this should not be happening!')
        return _create_mock_datakey()
    # Fernet key; from spec and cryptography implementation, but using
    # random from KMS, rather than os.urandom:
    #   https://github.com/fernet/spec/blob/master/Spec.md#key-format
    #   https://cryptography.io/en/latest/_modules/cryptography/fernet/#Fernet.generate_key
    key = base64.urlsafe_b64encode(
        kms.generate_random(NumberOfBytes=32)['Plaintext']
    )
    key_alias = app.config.get('KMS_MASTER_KEY')
    response = kms.encrypt(
        KeyId='alias/{0}'.format(key_alias),
        Plaintext=key,
        EncryptionContext=encryption_context

    )
    return {'ciphertext': response['CiphertextBlob'],
            'plaintext': key}


def _decrypt_mock_datakey(data_key):
    '''
    Mock decryption meant to be used for testing or development. Simply returns
    the provided data_key.
    '''
    return data_key


def decrypt_key(data_key, encryption_context=None):
    '''
    Decrypt a datakey.
    '''
    # Disabled encryption is dangerous, so we don't use falsiness here.
    if app.config['USE_ENCRYPTION'] is False:
        log.warning('Decypting a mock data key in keymanager.decrypt_key.'
                    ' If you are not running in a development or test'
                    ' environment, this should not be happening!')
        return _decrypt_mock_datakey(data_key)
    sha = hashlib.sha256(data_key).hexdigest()
    if sha not in DATAKEYS:
        plaintext = kms.decrypt(
            CiphertextBlob=data_key,
            EncryptionContext=encryption_context
        )['Plaintext']
        DATAKEYS[sha] = plaintext
    return DATAKEYS[sha]


def decrypt_token(token, _from):
    '''
    Decrypt a token.
    '''
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
            with stats.timer('kms_decrypt_token'):
                data = kms.decrypt(
                    CiphertextBlob=token,
                    EncryptionContext={
                        # This key is sent to us.
                        'to': app.config['AUTH_CONTEXT'],
                        # From a service.
                        'from': _from
                    }
                )
            # Decrypt doesn't take KeyId as an argument. We need to verify the
            # correct key was used to do the decryption.
            # Annoyingly, the KeyId from the data is actually an arn.
            key_arn = data['KeyId']
            if key_arn != get_key_arn(app.config['AUTH_KEY']):
                raise TokenDecryptionError('Authentication error.')
            plaintext = data['Plaintext']
            payload = json.loads(plaintext)
        # We don't care what exception is thrown. For paranoia's sake, fail
        # here.
        except Exception:
            log.exception('Failed to validate token.')
            raise TokenDecryptionError('Authentication error.')
    else:
        payload = TOKENS[token_key]
    time_format = "%Y%m%dT%H%M%SZ"
    now = datetime.datetime.utcnow()
    try:
        not_before = datetime.datetime.strptime(
            payload['not_before'],
            time_format
        )
        not_after = datetime.datetime.strptime(
            payload['not_after'],
            time_format
        )
    except Exception:
        log.exception(
            'Failed to get not_before and not_after from token payload.'
        )
        raise TokenDecryptionError('Authentication error.')
    delta = (not_after - not_before).seconds / 60
    if delta > app.config['AUTH_TOKEN_MAX_LIFETIME']:
        log.warning('Token used which exceeds max token lifetime.')
        raise TokenDecryptionError('Authentication error.')
    if not (now >= not_before) and (now <= not_after):
        log.warning('Expired token used.')
        raise TokenDecryptionError('Authentication error.')
    TOKENS[token_key] = payload
    return payload


def get_grants():
    _grants = []
    next_marker = None
    while True:
        if next_marker:
            grants = kms.list_grants(
                KeyId=get_key_id(app.config['AUTH_KEY']),
                Marker=next_marker,
                Limit=250
            )
        else:
            grants = kms.list_grants(
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
    try:
        role = iam.Role(name=service_name)
        role.load()
        grants = get_grants()
        _ensure_grants(role, grants)
    except ClientError:
        log.exception('Failed to ensure grants for {0}.'.format(service_name))
        raise ServiceCreateGrantError()


def grants_exist(service_name):
    try:
        role = iam.Role(name=service_name)
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
        log.exception('Failed to get grants for {0}.'.format(service_name))
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
    decrypt_constraint = {
        'EncryptionContextSubset': {
            'to': role.role_name
        }
    }
    encrypt_grant, decrypt_grant = _grants_exist(role, grants)
    if not encrypt_grant:
        log.info('Creating encrypt grant for {0}'.format(role.arn))
        kms.create_grant(
            KeyId=get_key_id(app.config['AUTH_KEY']),
            GranteePrincipal=role.arn,
            Operations=['Encrypt', 'Decrypt'],
            Constraints=encrypt_constraint
        )
    if not decrypt_grant:
        log.info('Creating decrypt grant for {0}'.format(role.arn))
        kms.create_grant(
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
