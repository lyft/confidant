import abc
import logging

import flask
from flask import abort, request, session, redirect

from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter

from confidant.app import app

from .errors import *

def init_user_auth_class():
    if not app.config['USE_AUTH']:
        module = NullUserAuthenticator

    else:
        module_name = app.config['USER_AUTH_MODULE'].lower()
        if module_name == 'google':
            module = GoogleOauthAuthenticator
        elif module_name == 'saml':
            module = SamlAuthenticator
        elif module_name == 'null':
            module = NullUserAuthenticator
        else:
            raise ValueError('Unknown USER_AUTH_MODULE: {!r}'.format(module_name))

    logging.info('Initializing {} user authenticator'.format(module.auth_type))
    return module()

class AbstractUserAuthenticator(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def auth_type(self):
        """A string describing the type of authentication used"""
        pass

    def is_authenticated(self):
        return 'user' in session

    def current_user(self):
        return session['user']

    def set_current_user(self, email, first_name, last_name):
        session['user'] = {
            'email': email,
            'first_name': first_name,
            'last_name': last_name,
        }

    def current_email(self):
        return self.current_user()['email'].lower()

    def current_first_name(self):
        return self.current_user()['first_name']

    def current_last_name(self):
        return self.current_user()['last_name']

    def redirect_to_index(self):
        return redirect(flask.url_for('index'))

    @abc.abstractmethod
    def log_in(self):
        """
        Perform steps needed to start the SSO login process.

        If  This method must
        return a Flask response.

        On success, this should be either a redirect to an external login page,
        or a redirect to the index page of this app (e.g. redirect_to_index()).

        On failure, this method will likely return abort(403).
        """
        pass

    @property
    def allowed_email_whitelist(self):
        """
        A whitelist of authorized email addresses or None.
        Loaded from config['USERS_FILE'] as YAML.
        """
        if not hasattr(self, '_email_whitelist'):
            self._email_whitelist = None
            if app.config.get('USERS_FILE'):
                with open(app.config['USERS_FILE'], 'r') as f:
                    self._email_whitelist = yaml.safe_load(f.read())

        return self._email_whitelist

    @property
    def allowed_email_suffix(self):
        """
        A whitelisted suffix for email addresses.
        Loaded from config['USER_EMAIL_SUFFIX'].

        Returns either a string or None.
        """

        return app.config['USER_EMAIL_SUFFIX']

    def check_authorization(self):
        email = self.current_email()

        if not self.passes_email_suffix(email):
            msg = 'User {!r} does not have email suffix {!r}'.format(
                email, self.allowed_email_suffix)
            raise NotAuthorized(msg)

        if not self.passes_email_whitelist(email):
            msg = 'User not in whitelist: {!r}'.format(
                email, self.allowed_email_whitelist)
            raise NotAuthorized(msg)

        return True

    def passes_email_suffix(self, email):
        if self.allowed_email_suffix:
            return email.endswith(self.allowed_email_suffix)
        else:
            return True

    def passes_email_whitelist(self, email):
        if self.allowed_email_whitelist is not None:
            return email in self.allowed_email_whitelist
        else:
            return True

class NullUserAuthenticator(object):
    """
    Fake user authenticator class that performs no authentication.
    """

    def __init__(self):
        # guard against using this when you think auth is in use
        assert not app.config['USE_AUTH']

    @property
    def auth_type(self):
        return 'null'

    def current_user(self):
        return {
            'email': 'unauthenticated user',
            'first_name': 'unauthenticated',
            'last_name': 'user',
        }

    def is_authenticated(self):
        """Null users are always authenticated"""
        return True

    def check_authorization(self):
        """Null users are always authorized"""
        return True

    def log_in(self):
        # should never be called
        raise NotImplementedError

class GoogleOauthAuthenticator(AbstractUserAuthenticator):
    """
    User authenticator class implementing Google OAuth.
    """

    def __init__(self):
        self.authomatic_config = {
            'google': {
                'class_': oauth2.Google,
                'consumer_key': app.config['GOOGLE_OAUTH_CLIENT_ID'],
                'consumer_secret': app.config['GOOGLE_OAUTH_CONSUMER_SECRET'],
                'scope': [
                    'profile',
                    'email'
                ]
            }
        }

        self.authomatic = Authomatic(
            self.authomatic_config,
            app.config['AUTHOMATIC_SALT']
        )

    @property
    def auth_type(self):
        return 'google oauth'

    def log_in(self):
        response = flask.make_response()
        result = self.authomatic.login(
            WerkzeugAdapter(request, response),
            'google',
            session=session,
            session_saver=lambda: app.save_session(session, response),
            secure_cookie=(True if request.is_secure else False)
        )
        if result:
            if result.error:
                msg = 'Google auth failed with error: {0}'
                logging.error(msg.format(result.error.message))
                return abort(403)

            # successful login
            if result.user:
                result.user.update()
                user = result.user
                self.set_current_user(email=user.email,
                                      first_name=user.first_name,
                                      last_name=user.last_name)
                # TODO: find a way to save the angular args?
                # authomatic adds url params google auth has stripped the
                # angular args anyway, so let's just redirect back to the
                # index.
                return self.redirect_to_index()

        # Authomatic will have put a redirect in our response here.
        return response


class SamlAuthenticator(AbstractUserAuthenticator):
    """
    User authenticator class implementing SAML.
    """

    @property
    def auth_type(self):
        return 'saml'

    def log_in(self):
        raise NotImplementedError

    def log_in_callback(self):
        raise NotImplementedError

