import unittest

from mock import patch

# Prevent call to KMS during tests
from confidant import settings
settings.encrypted_settings.secret_string = {}

from confidant.services import keymanager  # noqa:E402
from confidant.app import app  # noqa:E402


class KeyManagerTest(unittest.TestCase):
    def setUp(self):
        self.use_auth = app.config['USE_AUTH']
        self.use_encryption = app.config['USE_ENCRYPTION']
        self.scoped_auth_keys = app.config['SCOPED_AUTH_KEYS']

    def tearDown(self):
        app.config['USE_AUTH'] = self.use_auth
        app.config['USE_ENCRYPTION'] = self.use_encryption
        app.config['SCOPED_AUTH_KEYS'] = self.scoped_auth_keys

    @patch('confidant.services.keymanager.KEY_METADATA', {})
    @patch('confidant.services.keymanager.auth_kms_client.describe_key')
    def test_get_key_id(self, kms_mock):
        kms_mock.return_value = {'KeyMetadata': {'KeyId': 'mockid'}}
        self.assertEqual(
            keymanager.get_key_id('mockalias'),
            'mockid'
        )

    @patch(
        'confidant.services.keymanager.KEY_METADATA',
        {'mockalias': {'KeyMetadata': {'KeyId': 'mockid'}}}
    )
    @patch('confidant.services.keymanager.auth_kms_client.describe_key')
    def test_get_key_id_cached(self, kms_mock):
        self.assertEqual(
            keymanager.get_key_id('mockalias'),
            'mockid'
        )

    @patch('cryptography.fernet.Fernet.generate_key')
    def test_create_datakey_mocked(self, fernet_mock):
        app.config['USE_ENCRYPTION'] = False
        fernet_mock.return_value = 'mocked_fernet_key'

        ret = keymanager.create_datakey({})

        self.assertTrue(fernet_mock.called)

        # Assert that we got a dict returned where the ciphertext and plaintext
        # keys are equal
        self.assertEquals(ret['ciphertext'], ret['plaintext'])

        # Assert ciphertext is mocked_fernet_key
        self.assertEquals(ret['ciphertext'], 'mocked_fernet_key')

    def test_decrypt_datakey_mocked(self):
        app.config['USE_ENCRYPTION'] = False
        ret = keymanager.decrypt_datakey('mocked_fernet_key')

        # Ensure we get the same value out that we sent in.
        self.assertEquals(ret, 'mocked_fernet_key')

    @patch(
        'confidant.services.keymanager.cryptolib.create_datakey'
    )
    @patch(
        'confidant.services.keymanager.cryptolib.create_mock_datakey'
    )
    def test_create_datakey_with_encryption(self, cmd_mock, cd_mock):
        app.config['USE_ENCRYPTION'] = True
        context = {'from': 'confidant-development',
                   'to': 'confidant-development'}
        keymanager.create_datakey(context)

        # Assert that create_datakey was called and create_mock_datakey was
        # not called.
        self.assertTrue(cd_mock.called)
        self.assertFalse(cmd_mock.called)

    @patch(
        'confidant.services.keymanager.cryptolib.decrypt_datakey'
    )
    @patch(
        'confidant.services.keymanager.cryptolib.decrypt_mock_datakey'
    )
    def test_decrypt_datakey_with_encryption(self, dmd_mock, dd_mock):
        app.config['USE_ENCRYPTION'] = True
        context = {'from': 'confidant-development',
                   'to': 'confidant-development'}
        keymanager.decrypt_datakey(b'encrypted', context)

        # Assert that decrypt_datakey was called and decrypt_mock_datakey was
        # not called.
        self.assertTrue(dd_mock.called)
        self.assertFalse(dmd_mock.called)
