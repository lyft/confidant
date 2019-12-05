import hashlib
import logging
import botocore

from botocore.exceptions import ClientError

import confidant.clients
from confidant.app import app
from confidant.utils import stats
from confidant.lib import cryptolib

config = botocore.config.Config(
    connect_timeout=app.config['KMS_CONNECTION_TIMEOUT'],
    read_timeout=app.config['KMS_READ_TIMEOUT'],
    max_pool_connections=app.config['KMS_MAX_POOL_CONNECTIONS']
)
auth_kms_client = confidant.clients.get_boto_client(
    'kms',
    config={'name': 'keymanager', 'config': config}
)
at_rest_kms_client = confidant.clients.get_boto_client(
    'kms',
    config={'name': 'keymanager', 'config': config}
)
iam_resource = confidant.clients.get_boto_resource('iam')

DATAKEYS = {}
KEY_METADATA = {}


def get_key_id(key_alias):
    if key_alias not in KEY_METADATA:
        KEY_METADATA[key_alias] = auth_kms_client.describe_key(KeyId=key_alias)
    return KEY_METADATA[key_alias]['KeyMetadata']['KeyId']


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
        app.config.get('KMS_MASTER_KEY'),
        client=at_rest_kms_client
    )


def decrypt_datakey(data_key, encryption_context=None):
    '''
    Decrypt a datakey.
    '''
    # Disabled encryption is dangerous, so we don't use falsiness here.
    if app.config['USE_ENCRYPTION'] is False:
        logging.warning('Decrypting a mock data key in'
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
