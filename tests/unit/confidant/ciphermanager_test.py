import unittest
from nose.tools import assert_raises
from cryptography.fernet import Fernet

from confidant.ciphermanager import CipherManager
from confidant.ciphermanager import CipherManagerError


class CipherManagerTest(unittest.TestCase):
    def test_cipher_version_2(self):
        key = Fernet.generate_key()
        cipher = CipherManager(key, 2)
        ciphertext = cipher.encrypt('testdata')

        # Assert we're getting back some form of altered data
        self.assertNotEquals(ciphertext, 'testdata')

        cipher = CipherManager(key, 2)
        plaintext = cipher.decrypt(ciphertext).decode('UTF-8')

        # Assert that decrypting using a new cipher object with the same key
        # and version give back the same plaintext.
        self.assertEquals(plaintext, 'testdata')

    def test_cipher_version_1(self):
        key = Fernet.generate_key()
        cipher = CipherManager(key, 1)
        with assert_raises(CipherManagerError):
            cipher.encrypt('testdata')
        with assert_raises(CipherManagerError):
            cipher.decrypt('random_text')

    def test_cipher_version_3(self):
        key = Fernet.generate_key()
        cipher = CipherManager(key, 3)
        with assert_raises(CipherManagerError):
            cipher.encrypt('testdata')
        with assert_raises(CipherManagerError):
            cipher.decrypt('random_text')
