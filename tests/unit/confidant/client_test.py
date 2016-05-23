import unittest
import base64
import copy
import mock
import json
from mock import patch
from mock import MagicMock

import confidant.client


class FakeResponse(object):
    def __init__(self, url, code, content, encoding='utf-8', headers=None):
        self.url = url
        self.status_code = code
        self.code = code
        self.content = content
        self.text = str(content)
        self.encoding = encoding
        self.headers = headers or {}

    def json(self):
        return json.loads(self.content)


def request_200(method, url, *args, **kwargs):
    return FakeResponse(url, 200, '{}')
mock_200 = mock.Mock(wraps=request_200)


def request_404(method, url, *args, **kwargs):
    return FakeResponse(url, 404, '')
mock_404 = mock.Mock(wraps=request_404)


def request_500(method, url, *args, **kwargs):
    return FakeResponse(url, 500, '')
mock_500 = mock.Mock(wraps=request_500)


class ClientTest(unittest.TestCase):
    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test_validate_config(self):
        with self.assertRaises(confidant.client.ClientConfigurationError):
            confidant.client.ConfidantClient(
                'http://localhost/',
                'alias/authnz-testing',
                # Missing auth context. This causes a validation error
                {}
            )
        with self.assertRaises(confidant.client.ClientConfigurationError):
            confidant.client.ConfidantClient(
                'http://localhost/',
                'alias/authnz-testing',
                # Missing user_type context. This causes a validation error
                {'from': 'test', 'to': 'test'}
            )
        with self.assertRaises(confidant.client.ClientConfigurationError):
            confidant.client.ConfidantClient(
                'http://localhost/',
                'alias/authnz-testing',
                {'from': 'test', 'to': 'test', 'user_type': 'user'},
                # invalid token version
                token_version=3
            )
        assert(confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'test', 'to': 'test'},
            token_version=1
        ))
        assert(confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'test', 'to': 'test', 'user_type': 'service'}
        ))

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test__get_username(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest', 'to': 'test'},
            token_version=1
        )
        self.assertEqual(
            client._get_username(),
            'confidant-unittest'
        )
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
            token_version=2
        )
        self.assertEqual(
            client._get_username(),
            '2/service/confidant-unittest'
        )

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test__get_assume_role_creds(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
            token_version=2
        )
        client.sts_client.assume_role = MagicMock()
        client._get_assume_role_creds(
            'arn:aws:iam::12345:role/confidant-unittest'
        )
        # Ensure we generate base_arn, role_arn and username from passed-in
        # role
        client.sts_client.assume_role.assert_called_with(
            RoleArn='arn:aws:iam::12345:role/confidant-unittest',
            RoleSessionName='confidant-unittest_confidant'
        )
        client.iam_client = MagicMock()
        client.iam_client.get_user = MagicMock(return_value={
            'User': {
                'Arn': 'arn:aws:iam::12345:user/confidant-unittest2',
                'UserName': 'unittestuser'
            }
        })
        client._get_assume_role_creds('confidant-unittest2')
        # Ensure we generate base_arn, role_arn and username from get_user
        client.sts_client.assume_role.assert_called_with(
            RoleArn='arn:aws:iam::12345:role/confidant-unittest2',
            RoleSessionName='confidant-unittest2_confidant'
        )
        client._get_assume_role_creds('confidant-unittest2', mfa_pin='1234')
        # Ensure we generate base_arn, role_arn and username from get_user
        client.sts_client.assume_role.assert_called_with(
            RoleArn='arn:aws:iam::12345:role/confidant-unittest2',
            RoleSessionName='confidant-unittest2_confidant',
            SerialNumber='arn:aws:iam::12345:mfa/unittestuser',
            TokenCode='1234'
        )

    @patch(
        'confidant.services.get_boto_client'
    )
    def test__get_token(self, boto_mock):
        kms_mock = MagicMock()
        kms_mock.encrypt = MagicMock(
            return_value={'CiphertextBlob': 'encrypted'}
        )
        boto_mock.return_value = kms_mock
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        token = client._get_token()
        self.assertEqual(token, base64.b64encode('encrypted'))

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test__check_response_code(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        response = MagicMock
        response.status_code = 200
        self.assertTrue(client._check_response_code(response))
        self.assertTrue(client._check_response_code(response, [200]))
        response = MagicMock
        response.status_code = 200
        self.assertTrue(client._check_response_code(response))
        self.assertTrue(client._check_response_code(response, [200, 404]))
        response.status_code = 404
        response.text = 'failure'
        self.assertFalse(client._check_response_code(response))
        self.assertFalse(client._check_response_code(response, [200]))

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test_get_service(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        client._get_token = MagicMock()
        # Test 404. Should return True with no service entry since the call
        # succeeded, but the service didn't exist.
        client.request_session.request = mock_404
        self.maxDiff = None
        self.assertEqual(
            client.get_service(
                'confidant-development',
                False
            ),
            {'result': True}
        )
        # Test 200. Should return True with an empty dict, since that's how we
        # have the service mocked out.
        client.request_session.request = mock_200
        self.assertEqual(
            client.get_service(
                'confidant-development',
                False
            ),
            {'result': True, 'service': {}}
        )
        # Test 500. Should return False as the request failed.
        client.request_session.request = mock_500
        self.assertEqual(
            client.get_service(
                'confidant-development',
                False
            ),
            {'result': False}
        )
        # TODO: test decrypt_blind argument
        # TODO: test request exceptions

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test_get_blind_credential(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        client._get_token = MagicMock()
        client.request_session.request = mock_404
        self.maxDiff = None
        self.assertEqual(
            client.get_blind_credential(
                'confidant-development',
                False
            ),
            {'result': False}
        )
        client.request_session.request = mock_200
        self.assertEqual(
            client.get_blind_credential(
                'confidant-development',
                False
            ),
            {'result': True, 'blind_credential': {}}
        )
        client.request_session.request = mock_500
        self.assertEqual(
            client.get_blind_credential(
                'confidant-development',
                False
            ),
            {'result': False}
        )
        # TODO: test decrypt_blind argument
        # TODO: test request exceptions

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test__decrypt_blind_credentials(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        client._get_decrypted_pairs = MagicMock(
            return_value={'us-east-1': 'plaintext_secret'}
        )
        mock_creds = []
        self.assertEqual(
            client._decrypt_blind_credentials(mock_creds),
            []
        )
        mock_creds = [{'us-east-1': 'encrypted'}]
        self.assertEqual(
            client._decrypt_blind_credentials(mock_creds),
            [{
                'decrypted_credential_pairs': {
                    'us-east-1': 'plaintext_secret'
                },
                'us-east-1': 'encrypted'
            }]
        )

    @patch(
        'confidant.services.get_boto_client'
    )
    @patch(
        'confidant.lib.cryptolib.decrypt_datakey',
        MagicMock(return_value='encrypted_datakey')
    )
    def test__get_decrypted_pairs(self, boto_mock):
        config_mock = MagicMock()
        kms_mock = MagicMock()
        kms_mock._client_config = config_mock
        boto_mock.return_value = kms_mock
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
            region='us-east-1'
        )
        credential = {
            'metadata': {
                'context': {
                    'us-east-1': {
                        'group': 'unittest'
                    }
                }
            },
            'data_key': {
                # base64 encoded version of encrypted_datakey
                'us-east-1': 'ZW5jcnlwdGVkX2RhdGFrZXk='
            },
            'credential_pairs': {
                'us-east-1': 'plaintext_secret'
            }
        }
        with patch('confidant.client.Fernet') as MockFernet:
            mock_decrypt = MagicMock()
            mock_decrypt.return_value = '{"hello": "world"}'
            instance = MagicMock()
            instance.decrypt = mock_decrypt
            MockFernet.return_value = instance
            self.assertEqual(
                client._get_decrypted_pairs(credential),
                {'hello': 'world'}
            )

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    @patch(
        'confidant.lib.cryptolib.create_datakey',
        MagicMock(
            return_value={
                'ciphertext': 'encrypted_datakey',
                'plaintext': 'plaintext_datakey'
            }
        )
    )
    @patch(
        'boto3.session.Session',
        MagicMock(return_value=MagicMock())
    )
    def test__get_keys_and_encrypted_pairs(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        with patch('confidant.client.Fernet') as MockFernet:
            mock_encrypt = MagicMock()
            mock_encrypt.return_value = 'encrypted'
            instance = MagicMock()
            instance.encrypt = mock_encrypt
            MockFernet.return_value = instance
            self.assertEqual(
                client._get_keys_and_encrypted_pairs(
                    {'us-east-1': 'confidant-unittest-blind'},
                    {'us-east-1': {'group': 'confidant-unittest'}},
                    {'mockkey': 'mockval'},
                    'fernet',
                    2
                ),
                ({'us-east-1': 'ZW5jcnlwdGVkX2RhdGFrZXk='},
                 {'us-east-1': 'encrypted'})
            )

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test_create_blind_credential(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        client._get_token = MagicMock()
        client._get_keys_and_encrypted_pairs = MagicMock(
            return_value=(
                {
                    'us-east-1': 'ZW5jcnlwdGVkX2RhdGFrZXk='
                },
                {
                    'us-east-1': 'encrypted'
                }
            )
        )
        self.maxDiff = None
        client.request_session.request = mock_500
        self.assertEqual(
            client.create_blind_credential(
                {'us-east-1': 'confidant-development-blind'},
                {'us-east-1': {'group': 'confidant-development'}},
                'mock credential',
                {'mockkey': 'mockval'}
            ),
            {'result': False}
        )
        client.request_session.request = mock_200
        self.assertEqual(
            client.create_blind_credential(
                {'us-east-1': 'confidant-development-blind'},
                {'us-east-1': {'group': 'confidant-development'}},
                'mock credential',
                {'mockkey': 'mockval'}
            ),
            {'result': True, 'blind_credential': {}}
        )
        # TODO: test request exceptions

    @patch(
        'confidant.services.get_boto_client',
        MagicMock()
    )
    def test_update_blind_credential(self):
        client = confidant.client.ConfidantClient(
            'http://localhost/',
            'alias/authnz-testing',
            {'from': 'confidant-unittest',
             'to': 'test',
             'user_type': 'service'},
        )
        client._get_token = MagicMock()
        client._get_keys_and_encrypted_pairs = MagicMock(
            return_value=(
                {
                    'us-east-1': 'ZW5jcnlwdGVkX2RhdGFrZXk='
                },
                {
                    'us-east-1': 'encrypted'
                }
            )
        )
        get_blind_data = {
            'result': True,
            'blind_credential': {
                'revision': 1,
                'modified_by': 'testuser',
                # TODO: use a correctly formatted date here.
                'modified_date': '2015-01-01',
                'name': 'test secret',
                'metadata': {
                    'context': {
                        'us-east-1': {
                            'group': 'confidant-unittest'
                        }
                    }
                },
                'credential_pairs': {
                    'us-east-1': 'encrypted'
                },
                'cipher_type': 'fernet',
                'cipher_version': 2,
                'data_key': {
                    'us-east-1': 'ZW5jcnlwdGVkX2RhdGFrZXk='
                },
                'enabled': True
            }
        }
        client.get_blind_credential = MagicMock(
            return_value=copy.deepcopy(get_blind_data)
        )
        client.request_session.request = mock_500
        self.maxDiff = None
        self.assertEqual(
            client.update_blind_credential(
                '12345',
                {'us-east-1': 'confidant-development-blind'},
                {'us-east-1': {'group': 'confidant-development'}},
                'mock credential',
                {'mockkey': 'mockval'}
            ),
            {'result': False}
        )
        client.get_blind_credential = MagicMock(
            return_value=copy.deepcopy(get_blind_data)
        )
        client.request_session.request = mock_200
        self.assertEqual(
            client.update_blind_credential(
                '12345',
                {'us-east-1': 'confidant-development-blind'},
                {'us-east-1': {'group': 'confidant-development'}},
                'mock credential',
                {'mockkey': 'mockval'}
            ),
            {'result': True, 'blind_credential': {}}
        )
        # TODO: test all arguments
        # TODO: test request exceptions
