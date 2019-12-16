import unittest
from mock import patch

from confidant.encrypted_settings import EncryptedSettings


class EncprytedSettingsTest(unittest.TestCase):

    def test_register(self):
        enc_set = EncryptedSettings(None)
        enc_set.register('Foo', 'Bar')
        self.assertEqual(enc_set.secret_names, ['Foo'])

    def test_get_registered(self):
        enc_set = EncryptedSettings(None)
        enc_set.register('Foo', 'Bar')
        enc_set.decrypted_secrets = {'Foo': 'DecryptedBar'}
        self.assertEqual(enc_set.get_secret('Foo'), 'DecryptedBar')

    def test_get_registered_default(self):
        enc_set = EncryptedSettings(None)
        enc_set.register('Foo', 'Bar')
        enc_set.register('Bar', 'Baz')
        enc_set.decrypted_secrets = {'Foo': 'DecryptedFoo'}
        self.assertEqual(enc_set.get_secret('Bar'), 'Baz')

    @patch(
        'confidant.encrypted_settings.cryptolib.decrypt_datakey',
        return_value='1cVUbJT58SbMt4Wk4xmEZoNhZGdWO_vg1IJiXwc6HGs='
    )
    @patch(
        'confidant.encrypted_settings.Fernet.decrypt',
        return_value='{secret: value, secret2: value2}\n'
    )
    def test_bootstrap(self, mockdecryptkey, mockdecrypt):
        enc_set = EncryptedSettings(None)
        decrypted = enc_set._bootstrap(
            '{"secrets": "encryptedstring", "data_key": "dGhla2V5"}'
        )
        self.assertEqual(decrypted['secret2'], 'value2')

    def test_bootstrap_filefail(self):
        enc_set = EncryptedSettings(None)
        decrypted = enc_set._bootstrap('file://FILE/DOES/NOT/EXIST')
        self.assertEqual(decrypted, {})
