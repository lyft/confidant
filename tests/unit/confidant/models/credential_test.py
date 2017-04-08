import base64

import unittest

from mock import patch
from mock import MagicMock

from confidant.models.credential import Credential
from confidant.models.credential import EncryptError


class CredentialTest(unittest.TestCase):
    @patch(
        'confidant.keymanager.decrypt_datakey',
    )
    def test_decrypted_data_key(self, decrypt_mock):
        decrypt_mock.return_value = 'decrypted-data-key'
        data_key = (
            '{"us-east-1": "' +
            base64.b64encode('encrypted-data-key') +
            '"}'
        )
        cred = Credential(
            id='abcd1234-1',
            revision=1,
            schema_version=2,
            name='test credential',
            blind=True,
            data_type='archive-credential',
            data_key=data_key,
            credential_keys=[],
            metadata={},
            enabled=True,
            modified_by='tester'
        )

        # Can't decrypt a blind credential
        self.assertIsNone(cred.decrypted_data_key)

        cred.blind = False
        self.assertEqual(cred.decrypted_data_key, 'decrypted-data-key')
        decrypt_mock.assert_called_with(
            'encrypted-data-key',
            encryption_context={'id': 'abcd1234'}
        )

        cred.schema_version = 1
        cred.data_key = 'encrypted-data-key'
        self.assertEqual(cred.decrypted_data_key, 'decrypted-data-key')
        decrypt_mock.assert_called_with(
            'encrypted-data-key',
            encryption_context={'id': 'abcd1234'}
        )

        cred.id = 'abcd1234'
        cred.data_type = 'credential'
        self.assertEqual(cred.decrypted_data_key, 'decrypted-data-key')
        decrypt_mock.assert_called_with(
            'encrypted-data-key',
            encryption_context={'id': 'abcd1234'}
        )

    @patch(
        'confidant.keymanager.decrypt_datakey',
    )
    def test_decrypted_credential_pairs(self, decrypt_mock):
        decrypt_mock.return_value = 'decrypted-data-key'
        data_key = (
            '{"us-east-1": "' +
            base64.b64encode('encrypted-data-key') +
            '"}'
        )
        cred = Credential(
            id='abcd1234-1',
            revision=1,
            schema_version=2,
            cipher_version=2,
            name='test credential',
            blind=True,
            data_type='archive-credential',
            data_key=data_key,
            credential_keys=[],
            metadata={},
            enabled=True,
            modified_by='tester'
        )

        # Can't decrypt a blind credential
        self.assertIsNone(cred.decrypted_credential_pairs)

        cred.blind = False
        cred.credential_pairs = '{"us-east-1": "encrypted-cred-pairs"}'
        with patch('confidant.models.credential.CipherManager') as cipher_mock:
            decrypt_mock = MagicMock()
            decrypt_mock.decrypt = MagicMock(
                return_value='{"key": "val"}'
            )
            cipher_mock.return_value = decrypt_mock
            self.assertEqual(cred.decrypted_credential_pairs, {'key': 'val'})

        cred.schema_version = 1
        cred.credential_pairs = 'encrypted-cred-pairs'
        with patch('confidant.models.credential.CipherManager') as cipher_mock:
            decrypt_mock = MagicMock()
            decrypt_mock.decrypt = MagicMock(
                return_value='{"key": "val"}'
            )
            cipher_mock.return_value = decrypt_mock
            self.assertEqual(cred.decrypted_credential_pairs, {'key': 'val'})

    @patch(
        'confidant.keymanager.get_datakey_regions',
        MagicMock(return_value=['us-east-1'])
    )
    @patch(
        'confidant.keymanager.create_datakey',
        MagicMock(return_value={
            'ciphertext': 'encrypted-data-key-test-data',
            'plaintext': 'data-key-test-data'
        })
    )
    def test_encrypt_and_set_pairs(self):
        cred = Credential(
            id='abcd1234-1',
            revision=1,
            schema_version=2,
            name='test credential',
            blind=True,
            data_type='archive-credential',
            credential_keys=[],
            metadata={},
            enabled=True,
            modified_by='tester'
        )

        with self.assertRaisesRegexp(
                EncryptError,
                'Calling encrypt_and_set_pairs on a blind credential.'):
            cred.encrypt_and_set_pairs({'key': 'val'}, {'id': 'abcd1234'})

        cred.blind = False

        with patch('confidant.models.credential.CipherManager') as cipher_mock:
            encrypt_mock = MagicMock()
            encrypt_mock.encrypt = MagicMock(
                return_value='encrypted_data'
            )
            cipher_mock.return_value = encrypt_mock
            cred.encrypt_and_set_pairs({'key': 'val'}, {'id': 'abcd1234'})

            # These should be set.
            self.assertEqual(
                cred.credential_pairs,
                '{"us-east-1": "encrypted_data"}'
            )
            self.assertEqual(
                cred.data_key,
                ('{"us-east-1": "' +
                 base64.b64encode('encrypted-data-key-test-data') +
                 '"}')
            )
            self.assertEqual(cred.cipher_version, 2)
            self.assertEqual(cred.cipher_type, 'fernet')
