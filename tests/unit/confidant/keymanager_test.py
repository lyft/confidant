import unittest
from mock import patch

from confidant import keymanager
from confidant import app


class DataKeyTest(unittest.TestCase):
    @patch('cryptography.fernet.Fernet.generate_key')
    def test_create_datakey_mocked(self, fernet_mock):
        use_encryption = app.config['USE_ENCRYPTION']
        app.config['USE_ENCRYPTION'] = False
        fernet_mock.return_value = 'mocked_fernet_key'

        ret = keymanager.create_datakey({})

        self.assertTrue(fernet_mock.called)

        # Assert that we got a dict returned where the ciphertext and plaintext
        # keys are equal
        self.assertEquals(ret['ciphertext'], ret['plaintext'])

        # Assert ciphertext is mocked_fernet_key
        self.assertEquals(ret['ciphertext'], 'mocked_fernet_key')
        app.config['USE_ENCRYPTION'] = use_encryption

    def test_decrypt_key_mocked(self):
        use_encryption = app.config['USE_ENCRYPTION']
        app.config['USE_ENCRYPTION'] = False
        ret = keymanager.decrypt_key('mocked_fernet_key')

        # Ensure we get the same value out that we sent in.
        self.assertEquals(ret, 'mocked_fernet_key')
        app.config['USE_ENCRYPTION'] = use_encryption

    def test_datakey(self):
        use_encryption = app.config['USE_ENCRYPTION']
        app.config['USE_ENCRYPTION'] = True
        context = {'from': 'confidant-development',
                   'to': 'confidant-development'}
        ret = keymanager.create_datakey(context)

        # Assert that our ciphertext and plaintext aren't equal.
        self.assertNotEquals(ret['ciphertext'], ret['plaintext'])

        key = keymanager.decrypt_key(ret['ciphertext'], context)

        # Assert that our decrypted key is ciphertext is equal to the original
        # plaintext.
        self.assertEquals(ret['plaintext'], key)
        app.config['USE_ENCRYPTION'] = use_encryption
