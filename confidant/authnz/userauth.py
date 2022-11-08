import abc
import logging
import datetime
import random

import yaml
from six.moves.urllib.parse import urlparse

import flask
from flask import current_app, request, session
from flask import abort, jsonify, redirect
from werkzeug.security import safe_str_cmp

# google auth imports
from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter

# saml auth imports
from onelogin.saml2.auth import OneLogin_Saml2_Auth

from confidant import settings
from confidant.lib import cryptolib
from confidant.utils.misc import dict_deep_update
from confidant.authnz import errors

logger = logging.getLogger(__name__)


def init_user_auth_class(*args, **kwargs):
    if not settings.USE_AUTH:
        module = NullUserAuthenticator

    else:
        module_name = settings.USER_AUTH_MODULE.lower()
        if module_name == 'google':
            module = GoogleOauthAuthenticator
        elif module_name == 'saml':
            module = SamlAuthenticator
        elif module_name == 'header':
            module = HeaderAuthenticator
        elif module_name == 'null':
            module = NullUserAuthenticator
        else:
            raise ValueError(
                'Unknown USER_AUTH_MODULE: {!r}'.format(module_name))

    auth = module(*args, **kwargs)
    logger.info('Initializing {} user authenticator'.format(auth.auth_type))
    return auth


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
                logger.warning(
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
        return session.get(settings.XSRF_COOKIE_NAME)

    def set_csrf_token(self, resp):
        cookie_name = settings.XSRF_COOKIE_NAME
        if cookie_name not in session:
            session[cookie_name] = '{0:x}'.format(
                random.SystemRandom().getrandbits(160)
            )
        resp.set_cookie(cookie_name, session[cookie_name])

    def check_csrf_token(self):
        cookie_name = settings.XSRF_COOKIE_NAME
        token = request.headers.get('X-XSRF-TOKEN', '')
        if not token:
            return False
        return safe_str_cmp(token, session.get(cookie_name, ''))

    def set_expiration(self):
        if settings.PERMANENT_SESSION_LIFETIME:
            session.permanent = True
            now = datetime.datetime.utcnow()
            lifetime = settings.PERMANENT_SESSION_LIFETIME
            expiration = now + datetime.timedelta(seconds=lifetime)
            session['expiration'] = expiration
            # We want the max_expiration initially set, but we don't want it to
            # be extended.
            if not session.get('max_expiration'):
                max_lifetime = settings.MAX_PERMANENT_SESSION_LIFETIME
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
        ret = self.current_user()['email'].lower()
        # when migrating from 2 -> 3, the session email object may be bytes
        return ret.decode('UTF-8') if isinstance(ret, bytes) else ret

    def current_first_name(self):
        return self.current_user()['first_name']

    def current_last_name(self):
        return self.current_user()['last_name']

    def redirect_to_index(self):
        return redirect(flask.url_for('static_files.index'))

    def redirect_to_goodbye(self):
        return redirect(flask.url_for('static_files.goodbye'))

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
        logger.info('Using default log_out() method')
        self.clear_session()

        return self.redirect_to_goodbye()

    def clear_session(self):
        logger.info('Clearing flask session')
        session['user'] = {}
        session.clear()

    @property
    def allowed_email_whitelist(self):
        """
        A whitelist of authorized email addresses or None.
        Loaded from config['USERS_FILE'] as YAML.
        """
        # TODO: cache the _email_whitelist in memory, and check the file mtime
        # to determine if the cache needs to be refreshed.
        _email_whitelist = None
        if settings.USERS_FILE:
            with open(settings.USERS_FILE, 'r') as f:
                _email_whitelist = yaml.safe_load(f.read())

        return _email_whitelist

    @property
    def allowed_email_suffix(self):
        """
        A whitelisted suffix for email addresses.
        Loaded from config['USER_EMAIL_SUFFIX'].

        Returns either a string or None.
        """

        return settings.USER_EMAIL_SUFFIX

    def check_authorization(self):
        email = self.current_email()

        if not self.passes_email_suffix(email):
            msg = 'User {!r} does not have email suffix {!r}'.format(
                email, self.allowed_email_suffix)
            raise errors.NotAuthorized(msg)

        if not self.passes_email_whitelist(email):
            msg = 'User {!r} not in whitelist: {!r}'.format(
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


class NullUserAuthenticator(AbstractUserAuthenticator):
    """
    Fake user authenticator class that performs no authentication.
    """

    def __init__(self):
        # guard against using this when you think auth is in use
        assert not settings.USE_AUTH

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

    def is_expired(self):
        """Null users are never expired"""
        return False

    def check_authorization(self):
        """Null users are always authorized"""
        return True

    def log_in(self):
        # should never be called
        raise NotImplementedError


class HeaderAuthenticator(AbstractUserAuthenticator):
    """
    User authenticator that pulls user information from HTTP headers.
    Note that this assumes we're running behind some form of load-balancer or
    reverse proxy that performs the authentication, and that simply being able
    to make requests to this service implies that the user is authenticated.
    """

    def __init__(self):
        self.username_header = settings.HEADER_AUTH_USERNAME_HEADER
        self.email_header = settings.HEADER_AUTH_EMAIL_HEADER
        self.first_name_header = settings.get('HEADER_AUTH_FIRST_NAME_HEADER')
        self.last_name_header = settings.get('HEADER_AUTH_LAST_NAME_HEADER')

    @property
    def auth_type(self):
        return 'header'

    def assert_headers(self):
        """Asserts that the current request contains the appropriate headers."""
        if self.username_header not in request.headers:
            raise errors.UserUnknownError('No username header in request')

        if self.email_header not in request.headers:
            raise errors.UserUnknownError('No email header in request')

    def current_user(self):
        self.assert_headers()

        info = {
            'email': request.headers[self.email_header],

            # TODO: should we use a string like "unknown", fall back to the
            # email/username, ...?
            'first_name': '',
            'last_name': '',
        }

        if self.first_name_header and self.first_name_header in request.headers:
            info['first_name'] = request.headers[self.first_name_header]

        if self.last_name_header and self.last_name_header in request.headers:
            info['last_name'] = request.headers[self.last_name_header]

        return info

    def is_authenticated(self):
        """Any user that is able to make requests is authenticated"""
        self.assert_headers()
        return True

    def is_expired(self):
        """Sessions are not managed here and do not expire"""
        return False

    def check_authorization(self):
        """Header users are always authorized"""
        self.assert_headers()
        return True

    def log_in(self):
        self.assert_headers()

        # Does nothing, since simply being able to reach this endpoint is
        # 'logging in'.
        resp = self.redirect_to_index()
        self.set_csrf_token(resp)
        return resp


class GoogleOauthAuthenticator(AbstractUserAuthenticator):
    """
    User authenticator class implementing Google OAuth.
    """

    def __init__(self):
        self.authomatic_config = {
            'google': {
                'class_': oauth2.Google,
                'consumer_key': settings.GOOGLE_OAUTH_CLIENT_ID,
                'consumer_secret': settings.GOOGLE_OAUTH_CONSUMER_SECRET,
                'scope': [
                    'profile',
                    'email'
                ]
            }
        }

        self.authomatic = Authomatic(
            self.authomatic_config,
            settings.AUTHOMATIC_SALT
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
            session_saver=lambda: current_app.save_session(session, response),
            secure_cookie=(True if request.is_secure else False)
        )
        if result:
            if result.error:
                msg = 'Google auth failed with error: {0}'
                logger.error(msg.format(result.error))
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
        Given the configuration present in current_app.config, render a
        settings dict suitable for passing to OneLogin_Saml2_Auth() in
        initialization.
        """

        debug = settings.SAML_DEBUG
        if debug is None:
            debug = current_app.debug

        root_url = settings.SAML_CONFIDANT_URL_ROOT
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
        if settings.SAML_SP_KEY_FILE:
            sp_has_key = True
            sp_data['privateKey'] = self._load_rsa_for_saml(
                settings.SAML_SP_KEY_FILE,
                password=settings.get('SAML_SP_KEY_FILE_PASSWORD'))
        if settings.SAML_SP_KEY:
            sp_has_key = True
            sp_data['privateKey'] = settings.SAML_SP_KEY

        if settings.SAML_SP_CERT_FILE:
            sp_data['x509cert'] = self._load_x509_for_saml(
                settings.SAML_SP_CERT_FILE)
        if settings.SAML_SP_CERT:
            sp_data['x509cert'] = settings.SAML_SP_CERT

        # security defaults: sign everything if SP key was provided
        security_data = {
            'nameIdEncrypted': False,
            'authnRequestsSigned': sp_has_key,
            'logoutRequestsSigned': sp_has_key,
            'logoutResponsesSigned':
                settings.SAML_SECURITY_SLO_RESP_SIGNED,
            'signMetadata': sp_has_key,
            'wantMessagesSigned':
                settings.SAML_SECURITY_MESSAGES_SIGNED,
            'wantAssertionsSigned':
                settings.SAML_SECURITY_ASSERTIONS_SIGNED,
            'wantNameIdEncrypted': False,
            'wantAttributeStatement':
                settings.SAML_WANT_ATTRIBUTE_STATEMENT,
            "signatureAlgorithm": settings.SAML_SECURITY_SIG_ALGO,
        }

        # Identity provider section
        idp_data = {
            'entityId': settings.SAML_IDP_ENTITY_ID,
            'singleSignOnService': {
                'url': settings.SAML_IDP_SIGNON_URL,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            },
        }

        if settings.SAML_IDP_LOGOUT_URL:
            idp_data['singleLogoutService'] = {
                'url': settings.SAML_IDP_LOGOUT_URL,
                'binding': 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect'
            }

        if settings.SAML_IDP_CERT_FILE:
            idp_data['x509cert'] = self._load_x509_for_saml(
                settings.SAML_IDP_CERT_FILE)
        if settings.SAML_IDP_CERT:
            idp_data['x509cert'] = settings.SAML_IDP_CERT

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
        if settings.SAML_RAW_JSON_SETTINGS:
            logger.debug('overriding SAML settings from JSON')
            dict_deep_update(data, settings.SAML_RAW_JSON_SETTINGS)

        logger.debug('Rendered SAML settings: {!r}'.format(data))

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

        logger.debug('Processing SAML response')

        try:
            request_id = session['saml_authn_request_id']
        except KeyError:
            logger.warning('No saml_authn_request_id in session')
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
            logger.warning('auth.is_authenticated() => False')
            resp = jsonify(error='Not Authenticated')
            resp.status_code = 401
            return resp

        nameid = auth.get_nameid()
        logger.info('SAML user authenticated: {!r}'.format(nameid))

        attributes = auth.get_attributes()
        logger.info('SAML attributes: {!r}'.format(attributes))

        # normalize attributes by flattening single-item arrays
        for key, val in attributes.items():
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
        for key, val in attributes.items():
            if not getattr(key, 'lower', None):
                logger.error('Bad list attr {!r}'.format({key: val}))
            if key.lower() in ['firstname', 'first_name']:
                kwargs['first_name'] = val
            if key.lower() in ['lastname', 'last_name']:
                kwargs['last_name'] = val

        self.set_expiration()
        self.set_current_user(**kwargs)

        # success, redirect to RelayState if present or to /
        default_redirect = flask.url_for('static_files.index')
        redirect_url = request.form.get('RelayState', default_redirect)

        # avoid redirect loop
        # This is enough of a pain that it's not clear that we should even
        # support RelayState, but it seems good enough for now.
        if (redirect_url.endswith('/saml/consume') or
                redirect_url.endswith('/login')):
            redirect_url = default_redirect

        logger.debug("Redirecting to {0}".format(redirect_url))
        resp = flask.redirect(redirect_url)
        self.set_csrf_token(resp)
        return resp

    def log_out(self):
        """
        Initiate SAML SLO redirect.
        """

        logger.info('Initiating SAML logout request')

        try:
            current_nameid = self._current_user_nameid()
            current_session_id = self._current_saml_session_id()
        except errors.UserUnknownError:
            # must be already logged out
            logger.warning('No SAML data in session. Cannot SLO log out')
            self.clear_session()
            return self.redirect_to_goodbye()

        auth = self._saml_auth()

        # check for SLO support
        if not auth.get_slo_url():
            logger.warning('No SingleLogOut endpoint defined for IdP')
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

        logger.debug('Processing SAML logout response')

        auth = self._saml_auth()
        errors = []

        auth.process_slo()
        errors = auth.get_errors()
        if errors:
            if clear_session_on_errors:
                self.clear_session()

            return self._render_saml_errors_json(auth)

        logger.info('SAML SLO request was successful')
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

        url_data = urlparse(flask_request.url)

        if flask_request.scheme == 'https':
            https = 'on'
        elif current_app.debug and settings.SAML_FAKE_HTTPS:
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

        logger.warning('Handling SAML errors')
        data = {
            'message': 'SAML request failed',
            'errors': auth.get_errors(),
            'reason': auth.get_last_error_reason(),
            'request_id': auth.get_last_request_id(),
        }
        logger.warning('Errors: {0}'.format(data))

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
