import pytest
from cryptography.fernet import Fernet

from confidant.services.ciphermanager import CipherManager
from confidant.services.ciphermanager import CipherManagerError


def test_cipher_version_2():
    key = Fernet.generate_key()
    cipher = CipherManager(key, 2)
    ciphertext = cipher.encrypt('testdata')

    # Assert we're getting back some form of altered data
    assert ciphertext != 'testdata'

    cipher = CipherManager(key, 2)
    plaintext = cipher.decrypt(ciphertext).decode('UTF-8')

    # Assert that decrypting using a new cipher object with the same key
    # and version give back the same plaintext.
    assert plaintext == 'testdata'


def test_cipher_version_1():
    key = Fernet.generate_key()
    cipher = CipherManager(key, 1)
    with pytest.raises(CipherManagerError):
        cipher.encrypt('testdata')
    with pytest.raises(CipherManagerError):
        cipher.decrypt('random_text')


def test_cipher_version_3():
    key = Fernet.generate_key()
    cipher = CipherManager(key, 3)
    with pytest.raises(CipherManagerError):
        cipher.encrypt('testdata')
    with pytest.raises(CipherManagerError):
        cipher.decrypt('random_text')
