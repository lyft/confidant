import unittest
from mock import patch
from mock import Mock
from werkzeug.exceptions import Unauthorized

from confidant.app import app
from confidant import authnz


class AuthnzTest(unittest.TestCase):

    def setUp(self):
        self.use_auth = app.config['USE_AUTH']

    def tearDown(self):
        app.config['USE_AUTH'] = self.use_auth

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

    def test_user_type_has_privilege(self):
        self.assertTrue(
            authnz.user_type_has_privilege('user', 'random_function')
        )
        self.assertFalse(
            authnz.user_type_has_privilege('service', 'random_function')
        )
        self.assertTrue(
            authnz.user_type_has_privilege('service', 'get_service')
        )

    def test_require_csrf_token(self):
        mock_fn = Mock()
        mock_fn.__name__ = 'mock_fn'
        mock_fn.return_value = 'unittestval'

        wrapped = authnz.require_csrf_token(mock_fn)

        app.config['USE_AUTH'] = False
        self.assertEqual(wrapped(), 'unittestval')
        app.config['USE_AUTH'] = True
        with patch('confidant.authnz.g') as g_mock:
            g_mock.auth_type = 'kms'
            self.assertEqual(wrapped(), 'unittestval')
        with patch('confidant.authnz.g') as g_mock:
            g_mock.auth_type = 'google oauth'
            with patch('confidant.authnz.user_mod') as u_mock:
                u_mock.check_csrf_token = Mock(return_value=True)
                self.assertEqual(wrapped(), 'unittestval')
        with patch('confidant.authnz.g') as g_mock:
            g_mock.auth_type = 'google oauth'
            with patch('confidant.authnz.user_mod') as u_mock:
                u_mock.check_csrf_token = Mock(return_value=False)
                self.assertRaises(Unauthorized, wrapped)

    def test_user_is_service(self):
        app.config['USE_AUTH'] = False
        self.assertTrue(authnz.user_is_service('anything'))
        app.config['USE_AUTH'] = True
        with patch('confidant.authnz.g') as g_mock:
            g_mock.username = 'confidant-unitttest'
            self.assertTrue(authnz.user_is_service('confidant-unitttest'))
        with patch('confidant.authnz.g') as g_mock:
            g_mock.username = 'confidant-unitttest'
            self.assertFalse(authnz.user_is_service('notconfidant-unitttest'))

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

    def test_redirect_to_logout_if_no_auth(self):
        mock_fn = Mock()
        mock_fn.__name__ = 'mock_fn'
        mock_fn.return_value = 'unittestval'

        wrapped = authnz.redirect_to_logout_if_no_auth(mock_fn)

        with patch('confidant.authnz.user_mod') as u_mock:
            u_mock.is_expired = Mock(return_value=False)
            u_mock.is_authenticated = Mock(return_value=True)
            self.assertEqual(wrapped(), 'unittestval')
        with patch('confidant.authnz.user_mod') as u_mock:
            u_mock.is_expired = Mock(return_value=True)
            u_mock.redirect_to_goodbye = Mock(return_value='redirect_return')
            self.assertEqual(wrapped(), 'redirect_return')
        with patch('confidant.authnz.user_mod') as u_mock:
            u_mock.is_expired = Mock(return_value=False)
            u_mock.is_authenticated = Mock(return_value=False)
            u_mock.redirect_to_goodbye = Mock(return_value='redirect_return')
            self.assertEqual(wrapped(), 'redirect_return')
