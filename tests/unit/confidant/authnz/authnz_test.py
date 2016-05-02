import unittest
from mock import patch

from confidant.app import app
from confidant import authnz


class AuthnzTest(unittest.TestCase):

    def test_get_logged_in_user(self):
        with app.test_request_context('/v1/user/email'):
            with self.assertRaises(authnz.UserUnknownError):
                authnz.get_logged_in_user()
            with patch('confidant.authnz.g') as g_mock:
                g_mock.username = 'unittestuser'
                self.assertEqual(authnz.get_logged_in_user(), 'unittestuser')
            session_data = {
                'user': {'email': 'unittestuser@example.com'}
            }
            with patch('confidant.authnz.userauth.session', session_data):
                self.assertEqual(
                    authnz.get_logged_in_user(),
                    'unittestuser@example.com'
                )

    def test_user_is_user_type(self):
        use_auth = app.config['USE_AUTH']
        app.config['USE_AUTH'] = False
        self.assertTrue(authnz.user_is_user_type('anything'))
        app.config['USE_AUTH'] = True
        with patch('confidant.authnz.g') as g_mock:
            g_mock.user_type = 'user'
            self.assertTrue(authnz.user_is_user_type('user'))
        with patch('confidant.authnz.g') as g_mock:
            g_mock.user_type = 'service'
            self.assertTrue(authnz.user_is_user_type('service'))
        with patch('confidant.authnz.g') as g_mock:
            g_mock.user_type = 'user'
            self.assertFalse(authnz.user_is_user_type('service'))
        with patch('confidant.authnz.g') as g_mock:
            g_mock.user_type = 'service'
            self.assertFalse(authnz.user_is_user_type('user'))
        app.config['USE_AUTH'] = use_auth

    def test_user_is_service(self):
        use_auth = app.config['USE_AUTH']
        app.config['USE_AUTH'] = False
        self.assertTrue(authnz.user_is_service('anything'))
        app.config['USE_AUTH'] = True
        with patch('confidant.authnz.g') as g_mock:
            g_mock.username = 'confidant-unitttest'
            self.assertTrue(authnz.user_is_service('confidant-unitttest'))
        with patch('confidant.authnz.g') as g_mock:
            g_mock.username = 'confidant-unitttest'
            self.assertFalse(authnz.user_is_service('notconfidant-unitttest'))
        app.config['USE_AUTH'] = use_auth

    def test__parse_username(self):
        self.assertEqual(
            authnz._parse_username('confidant-unittest'),
            (1, 'service', 'confidant-unittest')
        )
        self.assertEqual(
            authnz._parse_username('2/service/confidant-unittest'),
            (2, 'service', 'confidant-unittest')
        )
        with self.assertRaisesRegexp(
                authnz.TokenVersionError,
                'Unsupported username format.'):
            authnz._parse_username('3/service/confidant-unittest/extratoken')

    def test__get_kms_auth_data(self):
        with app.test_request_context('/v1/user/email'):
            self.assertEqual(
                authnz._get_kms_auth_data(),
                {}
            )
        with patch('confidant.authnz.request') as request_mock:
            request_mock.authorization = {
                'username': 'confidant-unittest',
                'password': 'encrypted'
            }
            request_mock.headers = {}
            self.assertEqual(
                authnz._get_kms_auth_data(),
                {'version': 1,
                 'user_type': 'service',
                 'from': 'confidant-unittest',
                 'token': 'encrypted'}
            )
        with patch('confidant.authnz.request') as request_mock:
            request_mock.authorization = {
                'username': '2/user/testuser',
                'password': 'encrypted'
            }
            request_mock.headers = {}
            self.assertEqual(
                authnz._get_kms_auth_data(),
                {'version': 2,
                 'user_type': 'user',
                 'from': 'testuser',
                 'token': 'encrypted'}
            )
        with patch('confidant.authnz.request') as request_mock:
            request_mock.authorization = {}
            request_mock.headers = {
                'X-Auth-From': 'confidant-unittest',
                'X-Auth-Token': 'encrypted'
            }
            self.assertEqual(
                authnz._get_kms_auth_data(),
                {'version': 1,
                 'user_type': 'service',
                 'from': 'confidant-unittest',
                 'token': 'encrypted'}
            )
        with patch('confidant.authnz.request') as request_mock:
            request_mock.authorization = {}
            request_mock.headers = {
                'X-Auth-From': '2/user/testuser',
                'X-Auth-Token': 'encrypted'
            }
            self.assertEqual(
                authnz._get_kms_auth_data(),
                {'version': 2,
                 'user_type': 'user',
                 'from': 'testuser',
                 'token': 'encrypted'}
            )
        with patch('confidant.authnz.request') as request_mock:
            request_mock.authorization = {
                'username': 'confidant-unittest',
                'password': ''
            }
            request_mock.headers = {}
            with self.assertRaisesRegexp(
                    authnz.AuthenticationError,
                    'No password provided via basic auth.'
                    ):
                authnz._get_kms_auth_data(),
        with patch('confidant.authnz.request') as request_mock:
            request_mock.authorization = {}
            request_mock.headers = {
                'X-Auth-From': '2/user/testuser',
                'X-Auth-Token': ''
            }
            with self.assertRaisesRegexp(
                    authnz.AuthenticationError,
                    'No X-Auth-Token provided via auth headers.'
                    ):
                authnz._get_kms_auth_data(),
