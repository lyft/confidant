import unittest
from mock import patch
from mock import Mock

# Prevent call to KMS when app is imported
from confidant import settings
settings.encrypted_settings.secret_string = {}
settings.encrypted_settings.decrypted_secrets = {'SESSION_SECRET': 'TEST_KEY'}

from confidant.app import app
from confidant.encrypted_settings import EncryptedSettings


class EncprytedSettingsTest(unittest.TestCase):

    def test_app_config(self):
        # This is really an integration test
        assert app.config.get('SESSION_SECRET') == 'TEST_KEY'

    def test_register(self):
        enc_set = EncryptedSettings(None)
        enc_set.register('Foo', 'Bar')
        assert enc_set.secret_names == ['Foo']

    def test_get_registered(self):
        enc_set = EncryptedSettings(None)
        enc_set.register('Foo', 'Bar')
        enc_set.decrypted_secrets = {'Foo': 'DecryptedBar'}
        assert enc_set.get_secret('Foo') == 'DecryptedBar'

    def test_get_registered_default(self):
        enc_set = EncryptedSettings(None)
        enc_set.register('Foo', 'Bar')
        enc_set.register('Bar', 'Baz')
        enc_set.decrypted_secrets = {'Foo': 'DecryptedFoo'}
        assert enc_set.get_secret('Bar') == 'Baz'

    @patch('confidant.encrypted_settings.cryptolib.decrypt_datakey', return_value='1cVUbJT58SbMt4Wk4xmEZoNhZGdWO_vg1IJiXwc6HGs=')
    @patch('confidant.encrypted_settings.Fernet.decrypt', return_value='{secret: value, secret2: value2}\n')
    def test_bootstrap(self, mockdecryptkey, mockdecrypt):
        enc_set = EncryptedSettings(None)
        decrypted = enc_set._bootstrap('{"secrets": "encryptedstring", "data_key": "dGhla2V5"}')
        assert decrypted['secret2'] == 'value2'

    def test_bootstrap_filefail(self):
        enc_set = EncryptedSettings(None)
        decrypted = enc_set._bootstrap('file://FILE/DOES/NOT/EXIST')
        assert decrypted == {}
