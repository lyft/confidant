import unittest
import base64
from mock import patch
from mock import PropertyMock

from confidant.app import app
from confidant.authnz import userauth
from confidant import routes  # noqa


class AuthnzTest(unittest.TestCase):

    def setUp(self):
        self.test_client = app.test_client()
        self.email_suffix = app.config['USER_EMAIL_SUFFIX']
        app.config['USER_EMAIL_SUFFIX'] = ''
        self.use_auth = app.config['USE_AUTH']
        self.users_file = app.config['USERS_FILE']
        self.debug = app.debug

    def tearDown(self):
        app.config['USER_EMAIL_SUFFIX'] = self.email_suffix
        app.config['USE_AUTH'] = self.use_auth
        app.config['USERS_FILE'] = self.users_file
        app.debug = self.debug

    def test_auth_redirect(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        ret = self.test_client.get('/', follow_redirects=False)
        self.assertEquals(ret.status_code, 302)

    def test_no_auth(self):
        app.debug = True
        app.config['USE_AUTH'] = False
        user_mod = userauth.init_user_auth_class()
        with patch('confidant.authnz.user_mod', user_mod):
            ret = self.test_client.get('/v1/user/email')
            self.assertEquals(ret.status_code, 200)

    def test_auth_failure(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        ret = self.test_client.get('/v1/user/email', follow_redirects=False)
        self.assertEquals(ret.status_code, 401)

    def test_auth_with_email_session_in_users(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        # USERS_FILE needs to be set to test users file
        app.config['USERS_FILE'] = ''
        to_patch = ('confidant.authnz.userauth.AbstractUserAuthenticator.'
                    'allowed_email_whitelist')
        with patch(to_patch, new_callable=PropertyMock) as mock_whitelist:
            mock_whitelist.return_value = ['example@example.com']
            with self.test_client as c:
                with c.session_transaction() as session:
                    session['user'] = {'email': 'example@example.com'}
                ret = self.test_client.get(
                    '/v1/user/email',
                    follow_redirects=False
                )
            self.assertEquals(ret.status_code, 200)

    def test_auth_with_email_session_not_in_users(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        # USERS_FILE needs to be set to test users file
        app.config['USERS_FILE'] = ''
        to_patch = ('confidant.authnz.userauth.AbstractUserAuthenticator.'
                    'allowed_email_whitelist')
        with patch(to_patch, new_callable=PropertyMock) as mock_whitelist:
            mock_whitelist.return_value = ['example@example.com']
            with self.test_client as c:
                with c.session_transaction() as session:
                    session['user'] = {'email': 'baduser@example.com'}
                ret = self.test_client.get(
                    '/v1/user/email',
                    follow_redirects=False
                )
            self.assertEquals(ret.status_code, 403)

    def test_auth_with_email_session(self):
        app.debug = True
        # Unset the USERS_FILE, in case it's been set elsewhere
        app.config['USERS_FILE'] = ''
        app.config['USE_AUTH'] = True
        to_patch = ('confidant.authnz.userauth.AbstractUserAuthenticator.'
                    'allowed_email_whitelist')
        with patch(to_patch, new_callable=PropertyMock) as mock_whitelist:
            mock_whitelist.return_value = None
            with self.test_client as c:
                with c.session_transaction() as session:
                    session['user'] = {'email': 'example@example.com'}
                ret = self.test_client.get(
                    '/v1/user/email',
                    follow_redirects=False
                )
            self.assertEquals(ret.status_code, 200)

    def test_invalid_kms_auth_token(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        auth = base64.b64encode(
            '{0}:{1}'.format('confidant-development', 'faketoken')
        )
        ret = self.test_client.open(
            '/v1/services/confidant-development',
            'GET',
            headers={'Authorization': 'Basic {0}'.format(auth)},
            follow_redirects=False
        )
        self.assertEquals(ret.status_code, 403)

    @patch('confidant.keymanager.decrypt_token')
    def test_valid_kms_auth_token(self, keymanager_mock):
        app.debug = True
        app.config['USE_AUTH'] = True
        keymanager_mock.return_value = {"fake": "payload"}
        auth = base64.b64encode(
            '{0}:{1}'.format('confidant-development', 'faketoken')
        )
        ret = self.test_client.open(
            '/v1/services/confidant-development',
            'GET',
            headers={'Authorization': 'Basic {0}'.format(auth)},
            follow_redirects=False
        )
        self.assertEquals(ret.status_code, 404)

    @patch('confidant.keymanager.decrypt_token')
    def test_valid_kms_auth_token_invalid_user(self, keymanager_mock):
        app.debug = True
        app.config['USE_AUTH'] = True
        keymanager_mock.return_value = {"fake": "payload"}
        auth = base64.b64encode(
            '{0}:{1}'.format('confidant-development-baduser', 'faketoken')
        )
        ret = self.test_client.open(
            '/v1/services/confidant-development',
            'GET',
            headers={'Authorization': 'Basic {0}'.format(auth)},
            follow_redirects=False
        )
        self.assertEquals(ret.status_code, 401)
