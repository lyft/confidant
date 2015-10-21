import unittest
import base64
from mock import patch

from confidant import app


class AuthnzTest(unittest.TestCase):

    def setUp(self):
        self.test_client = app.test_client()

    def test_no_auth(self):
        app.debug = True
        app.config['USE_AUTH'] = False
        ret = self.test_client.get('/')
        self.assertEquals(ret.status_code, 200)

    def test_auth_redirect(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        ret = self.test_client.get('/', follow_redirects=False)
        self.assertEquals(ret.status_code, 302)

    @patch('confidant.authnz.users', ['example@example.com'])
    def test_auth_with_email_session_in_users(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        # USERS_FILE needs to be set to test users file
        app.config['USERS_FILE'] = '/dev/false'
        with self.test_client as c:
            with c.session_transaction() as session:
                session['google_oauth2'] = {'email': 'example@example.com'}
            ret = self.test_client.get('/', follow_redirects=False)
        self.assertEquals(ret.status_code, 200)

    @patch('confidant.authnz.users', ['example@example.com'])
    def test_auth_with_email_session_not_in_users(self):
        app.debug = True
        app.config['USE_AUTH'] = True
        # USERS_FILE needs to be set to test users file
        app.config['USERS_FILE'] = '/dev/false'
        with self.test_client as c:
            with c.session_transaction() as session:
                session['google_oauth2'] = {'email': 'baduser@example.com'}
            ret = self.test_client.get('/', follow_redirects=False)
        self.assertEquals(ret.status_code, 403)

    @patch('confidant.authnz.users', [])
    def test_auth_with_email_session(self):
        app.debug = True
        # Unset the USERS_FILE, in case it's been set elsewhere
        app.config['USERS_FILE'] = ''
        app.config['USE_AUTH'] = True
        with self.test_client as c:
            with c.session_transaction() as session:
                session['google_oauth2'] = {'email': 'example@example.com'}
            ret = self.test_client.get('/', follow_redirects=False)
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
