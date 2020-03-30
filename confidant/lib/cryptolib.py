import base64
from cryptography import x509
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


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


def load_x509_certificate_pem(path):
    """
    Load an X.509 PEM certificate from a file.

    :param path: The file path to an X.509 certificate in PEM format.
    :type path: string

    :returns: X.509 certificate object
    :rtype: cryptography.x509.Certificate
    """

    with open(path, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        return cert


def load_x509_certificate_pem_as_bare_base64(path):
    """
    Load an X.509 PEM certificate from a file, return as bare base64-encoded
    DER.

    :param path: The file path to an X.509 certificate in PEM format.
    :type path: string

    :returns: base64-encoded DER X.509 data.
    :rtype: string
    """
    return _x509_certificate_bare_base64(
        load_x509_certificate_pem(path))


def _x509_certificate_bare_base64(certificate):
    """
    Given a certificate object, return the base64 DER encoded certificate data.
    This looks like PEM encoding but without the -----BEGIN CERTIFICATE-----
    header and footer.

    :param certificate: The X.509 certificate
    :type certificate: cryptography.x509.Certificate

    :returns: base64-encoded DER X.509 data.
    :rtype: string
    """
    return base64.b64encode(certificate.public_bytes(
        serialization.Encoding.DER)).decode()


def load_private_key_pem(path, password=None):
    """
    Load an RSA private key from a file.

    :param path: The file path to an RSA private key in PEM format.
    :type path: string

    :param password: A password encrypting the file.
    :type password: string

    :returns: An RSA private key object.
    :rtype: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey
    """
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=password,
                                                  backend=default_backend())


def load_private_key_pem_as_bare_base64(path, password=None):
    """
    Load an RSA private key from a file as bare base64-encoded DER.

    :param path: The file path to an RSA private key in PEM format.
    :type path: string

    :param password: A password encrypting the file.
    :type password: string

    :returns: base64-encoded DER private key data.
    :rtype: string
    """
    return _rsa_private_key_bare_base64(
        load_private_key_pem(path, password=password)).decode()


def _rsa_private_key_bare_base64(key):
    """
    Given an RSA private key, return the base64 + DER encoded private key data.
    This looks like PEM encoding but without the -----BEGIN PRIVATE KEY-----
    header and footer.

    :param key: The RSA private key
    :type key: cryptography.hazmat.primitives.asymmetric.rsa.RSAPrivateKey

    :returns: base64-encoded DER private key data.
    :rtype: string
    """
    return base64.b64encode(
        key.private_bytes(serialization.Encoding.DER,
                          format=serialization.PrivateFormat.TraditionalOpenSSL,
                          encryption_algorithm=serialization.NoEncryption()))
