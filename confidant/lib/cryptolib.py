import base64
from cryptography.fernet import Fernet

import confidant.services


def decrypt_mock_datakey(data_key):
    '''
    Mock decryption meant to be used for testing or development. Simply returns
    the provided data_key.
    '''
    return data_key


def decrypt_datakey(data_key, encryption_context=None, client=None):
    '''
    Decrypt a datakey.
    '''
    if not client:
        client = confidant.services.get_boto_client('kms')
    return client.decrypt(
        CiphertextBlob=data_key,
        EncryptionContext=encryption_context
    )['Plaintext']


def create_mock_datakey():
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


def create_datakey(encryption_context, keyid, client=None):
    '''
    Create a datakey from KMS.
    '''
    if not client:
        client = confidant.services.get_boto_client('kms')
    # Fernet key; from spec and cryptography implementation, but using
    # random from KMS, rather than os.urandom:
    #   https://github.com/fernet/spec/blob/master/Spec.md#key-format
    #   https://cryptography.io/en/latest/_modules/cryptography/fernet/#Fernet.generate_key
    key = base64.urlsafe_b64encode(
        client.generate_random(NumberOfBytes=32)['Plaintext']
    )
    response = client.encrypt(
        KeyId='{0}'.format(keyid),
        Plaintext=key,
        EncryptionContext=encryption_context

    )
    return {'ciphertext': response['CiphertextBlob'],
            'plaintext': key}
