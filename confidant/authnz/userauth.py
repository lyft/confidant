import abc
import logging
import urlparse
import datetime
import random

import yaml

import flask
from flask import request, session
from flask import abort, jsonify, redirect
from werkzeug.security import safe_str_cmp

# google auth imports
from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter

# saml auth imports
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from confidant.lib import cryptolib
from confidant.utils.misc import dict_deep_update

from confidant.app import app

from confidant.authnz import errors


def init_user_auth_class(*args, **kwargs):
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
            raise ValueError(
                'Unknown USER_AUTH_MODULE: {!r}'.format(module_name))

    logging.info('Initializing {} user authenticator'.format(module.auth_type))
    return module(*args, **kwargs)


class AbstractUserAuthenticator(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractproperty
    def auth_type(self):
        """A string describing the type of authentication used"""
        pass

    def is_authenticated(self):
        return 'user' in session

    def is_expired(self):
        if 'expiration' in session:
            # Paranoia case
            if session.get('max_expiration') is None:
                logging.warning(
                    'max_expiration unset on session, when expiration is set.'
                )
                return True
            now = datetime.datetime.utcnow()
            if now > session['expiration']:
                return True
            elif now > session['max_expiration']:
                return True
        else:
            return False

    def current_user(self):
        return session['user']

    def get_csrf_token(self):
        return session.get('XSRF-TOKEN')

    def set_csrf_token(self, resp):
        session['XSRF-TOKEN'] = '{0:x}'.format(
            random.SystemRandom().getrandbits(160)
        )
        resp.set_cookie('XSRF-TOKEN', session['XSRF-TOKEN'])

    def check_csrf_token(self):
        token = request.headers.get('X-XSRF-TOKEN', '')
        if not token:
            return False
        return safe_str_cmp(token, session.get('XSRF-TOKEN', ''))

    def set_expiration(self):
        if app.config['PERMANENT_SESSION_LIFETIME']:
            session.permanent = True
            now = datetime.datetime.utcnow()
            lifetime = app.config['PERMANENT_SESSION_LIFETIME']
            expiration = now + datetime.timedelta(seconds=lifetime)
            session['expiration'] = expiration
            # We want the max_expiration initially set, but we don't want it to
            # be extended.
            if not session.get('max_expiration'):
                max_lifetime = app.config['MAX_PERMANENT_SESSION_LIFETIME']
                if not max_lifetime:
                    max_lifetime = lifetime
                max_expiration = now + datetime.timedelta(seconds=max_lifetime)
                session['max_expiration'] = max_expiration

    def set_current_user(self, email, first_name=None, last_name=None):
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

    def redirect_to_goodbye(self):
        return redirect(flask.url_for('goodbye'))

    @abc.abstractmethod
    def log_in(self):
        """
        Perform steps needed to start the SSO login process.

        This method must return a Flask response.

        Initially this method will probably return a redirect to an external
        login page for SSO.

        This handler MAY also be used to handle login callbacks from the SSO
        provider, or you can define a separate route for this. Regardless, the
        code that implements the callback should call set_current_user() to set
        user data on the session, then redirect to the desired post-login page
        (e.g. with redirect_to_index()).

        On failure, this method should likely return abort(403).
        """
        pass

    def log_out(self):
        """
        Perform steps needed to start the SLO (SingleLogOut) process.

        This method must return a Flask response.

        This handler MAY also be used to handle logout callbacks from the
        SSO/SLO provider, or you can define a separate route for this.
        Regardless, the code that implements the callback should call
        clear_session(), then redirect to the desired post-logout page
        (e.g. with redirect_to_goodbye()).
        """
        logging.info('Using default log_out() method')
        self.clear_session()

        return self.redirect_to_goodbye()

    def clear_session(self):
        logging.info('Clearing flask session')
        session['user'] = {}
        session.clear()

    @property
    def allowed_email_whitelist(self):
        """
        A whitelist of authorized email addresses or None.
        Loaded from config['USERS_FILE'] as YAML.
        """
        if not hasattr(self, '_email_whitelist'):
            self._email_whitelist = None
            if app.config['USERS_FILE']:
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
            raise errors.NotAuthorized(msg)

        if not self.passes_email_whitelist(email):
            msg = 'User not in whitelist: {!r}'.format(
                email, self.allowed_email_whitelist)
            raise errors.NotAuthorized(msg)

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

    def current_email(self):
        return self.current_user()['email'].lower()

    def current_first_name(self):
        return self.current_user()['first_name']

    def current_last_name(self):
        return self.current_user()['last_name']

    def is_authenticated(self):
        """Null users are always authenticated"""
        return True

    def is_expired(self):
        """Null users are never expired"""
        return False

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
                self.set_expiration()
                self.set_current_user(email=user.email,
                                      first_name=user.first_name,
                                      last_name=user.last_name)
                # TODO: find a way to save the angular args?
                # authomatic adds url params google auth has stripped the
                # angular args anyway, so let's just redirect back to the
                # index.
                resp = self.redirect_to_index()
                self.set_csrf_token(resp)
                return resp

        # Authomatic will have put a redirect in our response here.
        return response


class SamlAuthenticator(AbstractUserAuthenticator):
    """
    User authenticator class implementing SAML.
    """

    @property
    def auth_type(self):
        return 'saml'

    def __init__(self):
        self.saml_config = self._render_saml_settings_dict()

    def _load_x509_for_saml(self, path):
        """Load an X.509 certificate from a PEM file."""
        return cryptolib.load_x509_certificate_pem_as_bare_base64(path)

    def _load_rsa_for_saml(self, path, password=None):
        """Load an RSA private key file."""
        return cryptolib.load_private_key_pem_as_bare_base64(path,
                                                             password=password)

    def _render_saml_settings_dict(self):
        """
        Given the configuration present in app.config, render a settings dict
        suitable for passing to OneLogin_Saml2_Auth() in initialization.
        """

        debug = app.config['SAML_DEBUG']
        if debug is None:
            debug = app.debug

        root_url = app.config['SAML_CONFIDANT_URL_ROOT']
        if not root_url:
            raise ValueError("Must provide SAML_CONFIDANT_URL_ROOT")
        root_url = root_url.rstrip('/')

        # TODO: also support unspecified?
        name_id_fmt = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress'

        # Service Provider section
        sp_data = {
            'entityId': root_url + '/v1/saml/metadata',
            'assertionConsumerService': {
                'url': root_url + '/v1/saml/consume',
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST'
            },
            'singleLogoutService': {
                'url': root_url + '/v1/saml/logout',
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-REDIRECT'
            },
            'NameIDFormat': name_id_fmt,
        }

        sp_has_key = False
        if app.config['SAML_SP_KEY_FILE']:
            sp_has_key = True
            sp_data['privateKey'] = self._load_rsa_for_saml(
                app.config['SAML_SP_KEY_FILE'],
                password=app.config.get('SAML_SP_KEY_FILE_PASSWORD'))
        if app.config['SAML_SP_KEY']:
            sp_has_key = True
            sp_data['privateKey'] = app.config['SAML_SP_KEY']

        if app.config['SAML_SP_CERT_FILE']:
            sp_data['x509cert'] = self._load_x509_for_saml(
                app.config['SAML_SP_CERT_FILE'])
        if app.config['SAML_SP_CERT']:
            sp_data['x509cert'] = app.config['SAML_SP_CERT']

        # security defaults: sign everything if SP key was provided
        security_data = {
            'nameIdEncrypted': False,
            'authnRequestsSigned': sp_has_key,
            'logoutRequestsSigned': sp_has_key,
            'logoutResponsesSigned':
                app.config['SAML_SECURITY_SLO_RESP_SIGNED'],
            'signMetadata': sp_has_key,
            'wantMessagesSigned':
                app.config['SAML_SECURITY_MESSAGES_SIGNED'],
            'wantAssertionsSigned':
                app.config['SAML_SECURITY_ASSERTIONS_SIGNED'],
            'wantNameIdEncrypted': False,
            "signatureAlgorithm": app.config['SAML_SECURITY_SIG_ALGO'],
        }

        # Identity provider section
        idp_data = {
            'entityId': app.config['SAML_IDP_ENTITY_ID'],
            'singleSignOnService': {
                'url': app.config['SAML_IDP_SIGNON_URL'],
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            },
        }

        if app.config['SAML_IDP_LOGOUT_URL']:
            idp_data['singleLogoutService'] = {
                'url': app.config['SAML_IDP_LOGOUT_URL'],
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            }

        if app.config['SAML_IDP_CERT_FILE']:
            idp_data['x509cert'] = self._load_x509_for_saml(
                app.config['SAML_IDP_CERT_FILE'])
        if app.config['SAML_IDP_CERT']:
            idp_data['x509cert'] = app.config['SAML_IDP_CERT']

        # put it all together into the settings
        data = {
            'strict': True,  # must not be changed for security
            'debug': debug,
            'sp': sp_data,
            'idp': idp_data,
            'security': security_data,
        }

        # if SAML_RAW_JSON_SETTINGS is set, merge the settings in, doing one
        # level of deep merging.
        if app.config['SAML_RAW_JSON_SETTINGS']:
            logging.debug('overriding SAML settings from JSON')
            dict_deep_update(data, app.config['SAML_RAW_JSON_SETTINGS'])

        logging.debug('Rendered SAML settings: {!r}'.format(data))

        return data

    def log_in(self):
        """
        SAML log-in redirect.

        This method initiates the SAML authentication process by directing the
        browser to forward along an AuthNRequest to the IdP.

        A separate method handles the post-authentication callback, which will
        hit /v1/saml/consume, processed by consume_saml_assertion().
        """

        self_page = request.script_root + request.path

        return flask.redirect(self.login_redirect_url(return_to=self_page))

    def consume_saml_assertion(self):
        """
        This method is called in routes implementing a SAML attribute consumer
        service, which receives POST callbacks from the IdP after the user has
        authenticated.
        """

        auth = self._saml_auth()

        logging.debug('Processing SAML response')

        try:
            request_id = session['saml_authn_request_id']
        except KeyError:
            logging.warning('No saml_authn_request_id in session')
            resp = jsonify(errors=['invalid_response'],
                           message='SAML request failed',
                           reason=('No AuthNRequest ID from SP found '
                                   'to match with InResponseTo of response'))
            resp.status_code = 401
            return resp

        auth.process_response(request_id=request_id)

        if auth.get_errors():
            return self._render_saml_errors_json(auth)

        session.pop('saml_authn_request_id', None)

        if not auth.is_authenticated():
            logging.warning('auth.is_authenticated() => False')
            resp = jsonify(error='Not Authenticated')
            resp.status_code = 401
            return resp

        nameid = auth.get_nameid()
        logging.info('SAML user authenticated: {!r}'.format(nameid))

        attributes = auth.get_attributes()
        logging.info('SAML attributes: {!r}'.format(attributes))

        # normalize attributes by flattening single-item arrays
        for key, val in attributes.iteritems():
            if isinstance(val, list) and len(val) == 1:
                attributes[key] = val[0]

        session['saml_data'] = {
            'attrs': attributes,
            'nameid': nameid,
            'session_index': auth.get_session_index()
        }

        kwargs = {}

        # use email from attributes if present, else nameid
        kwargs['email'] = attributes.get('email', nameid)

        # use first_name, last_name if present
        for key, val in attributes.iteritems():
            if not getattr(key, 'lower', None):
                logging.error('Bad list attr {!r}'.format({key: val}))
            if key.lower() in ['firstname', 'first_name']:
                kwargs['first_name'] = val
            if key.lower() in ['lastname', 'last_name']:
                kwargs['last_name'] = val

        self.set_expiration()
        self.set_current_user(**kwargs)

        # success, redirect to RelayState if present or to /
        default_redirect = flask.url_for('index')
        redirect_url = request.form.get('RelayState', default_redirect)

        # avoid redirect loop
        # This is enough of a pain that it's not clear that we should even
        # support RelayState, but it seems good enough for now.
        if (redirect_url.endswith('/saml/consume') or
            redirect_url.endswith('/login')):
            redirect_url = default_redirect

        logging.debug("Redirecting to {0}".format(redirect_url))
        resp = flask.redirect(redirect_url)
        self.set_csrf_token(resp)
        return resp

    def log_out(self):
        """
        Initiate SAML SLO redirect.
        """

        logging.info('Initiating SAML logout request')

        try:
            current_nameid = self._current_user_nameid()
            current_session_id = self._current_saml_session_id()
        except errors.UserUnknownError:
            # must be already logged out
            logging.warning('No SAML data in session. Cannot SLO log out')
            self.clear_session()
            return self.redirect_to_goodbye()

        auth = self._saml_auth()

        # check for SLO support
        if not auth.get_slo_url():
            logging.warning('No SingleLogOut endpoint defined for IdP')
            self.clear_session()
            return self.redirect_to_goodbye()

        # TODO: decide whether to always clear the session here or not. Relying
        # on the IDP to redirect back to us hasn't been super reliable.
        self.clear_session()

        # redirect to SLO endpoint
        return flask.redirect(auth.logout(name_id=current_nameid,
                                          session_index=current_session_id))

    def log_out_callback(self, clear_session_on_errors=True):
        """
        Callback for SAML logout requests.

        Request must have a SAMLResponse GET parameter.

        On failure, renders error JSON. On success, redirects to /goodbye.
        """

        logging.debug('Processing SAML logout response')

        auth = self._saml_auth()
        errors = []

        auth.process_slo()
        errors = auth.get_errors()
        if errors:
            if clear_session_on_errors:
                self.clear_session()

            return self._render_saml_errors_json(auth)

        logging.info('SAML SLO request was successful')
        self.clear_session()

        return self.redirect_to_goodbye()

    def _saml_auth(self, req_dict=None):
        """
        Instantiate a OneLogin_Saml2_Auth object from the current request data
        (or from req_dict, if given).

        :param req_dict: A dict containing request information, optional.
        :type req_dict: dict

        :returns: a SAML Auth object
        :rtype: onelogin.saml2.auth.OneLogin_Saml2_Auth
        """
        if req_dict is None:
            req_dict = self._saml_req_dict_from_request()

        auth = OneLogin_Saml2_Auth(req_dict, self.saml_config)
        return auth

    def _saml_req_dict_from_request(self, flask_request=None):
        """
        Given a Flask Request object, return a dict of request information in
        the format that python-saml expects it for Auth objects.

        :param flask_request: A request object to pull data from.
        :type flask_request: flask.Request

        :returns: python-saml settings data
        :rtype: dict
        """
        if flask_request is None:
            flask_request = flask.request

        url_data = urlparse.urlparse(flask_request.url)

        if flask_request.scheme == 'https':
            https = 'on'
        elif app.debug and app.config['SAML_FAKE_HTTPS']:
            https = 'on'
        else:
            https = 'off'

        return {
            'https': https,
            'http_host': flask_request.host,
            'server_port': url_data.port,
            'script_name': flask_request.path,
            'get_data': flask_request.args.copy(),
            'post_data': flask_request.form.copy(),
        }

    def _current_user_nameid(self):
        """Get the SAML name_id of the currently logged in user."""
        if 'saml_data' in session:
            return session['saml_data']['nameid']
        else:
            raise errors.UserUnknownError('No SAML user data in session')

    def _current_saml_session_id(self):
        if 'saml_data' in session:
            return session['saml_data']['session_index']
        else:
            raise errors.UserUnknownError('No SAML user data in session')

    def generate_metadata(self):
        """
        Generate SAML metadata XML describing the service endpoints.
        """
        auth = self._saml_auth()
        settings = auth.get_settings()
        metadata = settings.get_sp_metadata()
        errors = settings.validate_metadata(metadata)

        if errors:
            resp = flask.make_response(errors.join(', '), 500)
            resp.headers['Content-Type'] = 'text/plain'
        else:
            resp = flask.make_response(metadata, 200)
            resp.headers['Content-Type'] = 'text/xml'

        return resp

    def _render_saml_errors_json(self, auth):
        """
        Log and handle SAML errors, returning as json.
        Return a Response object appropriate to return in a route handler.

        :param auth: The python-saml Auth class.
        :type auth: onelogin.saml2.auth.OneLogin_Saml2_Auth

        :returns: a flask response
        :rtype: flask.Response
        """

        logging.warn('Handling SAML errors')
        data = {
            'message': 'SAML request failed',
            'errors': auth.get_errors(),
            'reason': auth.get_last_error_reason(),
            'request_id': auth.get_last_request_id(),
        }
        logging.warn('Errors: {0}'.format(data))

        resp = jsonify(**data)
        resp.status_code = 500
        return resp

    def login_redirect_url(self, return_to='/', auth=None):
        if auth is None:
            auth = self._saml_auth()

        login_url = auth.login(return_to=return_to)

        # store request ID in session so we can verify
        session['saml_authn_request_id'] = auth.get_last_request_id()

        return login_url
