import logging

import kmsauth
from flask import abort, request, g, make_response
from flask import url_for
from functools import wraps

from confidant import settings
from confidant.utils import stats

from confidant.authnz.errors import (
    UserUnknownError,
    AuthenticationError,
    NotAuthorized,
)
from confidant.authnz import userauth

_VALIDATOR = None

logger = logging.getLogger(__name__)
user_mod = userauth.init_user_auth_class()


def _get_validator():
    global _VALIDATOR
    if _VALIDATOR is None:
        _VALIDATOR = kmsauth.KMSTokenValidator(
            settings.AUTH_KEY,
            settings.USER_AUTH_KEY,
            settings.AUTH_CONTEXT,
            settings.AWS_DEFAULT_REGION,
            auth_token_max_lifetime=settings.AUTH_TOKEN_MAX_LIFETIME,
            minimum_token_version=settings.KMS_MINIMUM_TOKEN_VERSION,
            maximum_token_version=settings.KMS_MAXIMUM_TOKEN_VERSION,
            scoped_auth_keys=settings.SCOPED_AUTH_KEYS,
            token_cache_size=settings.KMS_AUTH_TOKEN_CACHE_SIZE,
            stats=stats,
            endpoint_url=settings.KMS_URL,
        )
    return _VALIDATOR


def get_logged_in_user():
    '''
    Retrieve logged-in user's email that is stored in cache
    '''
    if hasattr(g, 'username'):
        return g.username
    if user_mod.is_authenticated():
        return user_mod.current_email()
    raise UserUnknownError()


def user_is_user_type(user_type):
    if not settings.USE_AUTH:
        return True
    if user_type == g.user_type:
        return True
    return False


def user_is_service(service):
    if not settings.USE_AUTH:
        return True
    if hasattr(g, 'username'):
        if g.username == service:
            return True
    return False


def service_in_account(account):
    # We only scope to account, if an account is specified.
    if not account:
        return True
    if g.account == account:
        return True
    return False


def account_for_key_alias(key_alias):
    return settings.SCOPED_AUTH_KEYS.get(key_alias)


def require_csrf_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        # If we're not using auth, there's no point in checking csrf tokens.
        if not settings.USE_AUTH:
            return f(*args, **kwargs)
        # KMS is username/password or header auth, so we don't need to check
        # for csrf tokens.
        if g.auth_type == 'kms':
            return f(*args, **kwargs)
        if user_mod.check_csrf_token():
            return f(*args, **kwargs)
        return abort(401)
    return decorated


def _get_kms_auth_data():
    data = {}
    auth = request.authorization
    headers = request.headers
    if auth and auth.get('username'):
        if not auth.get('password'):
            raise AuthenticationError('No password provided via basic auth.')
        data['username'] = auth['username']
        data['token'] = auth['password']
    elif 'X-Auth-Token' in headers and 'X-Auth-From' in headers:
        if not headers.get('X-Auth-Token'):
            raise AuthenticationError(
                'No X-Auth-Token provided via auth headers.'
            )
        data['username'] = headers['X-Auth-From']
        data['token'] = headers['X-Auth-Token']
    return data


def log_in():
    return user_mod.log_in()


def redirect_to_logout_if_no_auth(f):
    """
    Decorator for redirecting users to the logout page when they are
    not authenticated.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if user_mod.is_expired():
            return user_mod.redirect_to_goodbye()

        if user_mod.is_authenticated():
            return f(*args, **kwargs)
        else:
            return user_mod.redirect_to_goodbye()
    return decorated


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not settings.USE_AUTH:
            return f(*args, **kwargs)

        # User suppplied basic auth info
        try:
            kms_auth_data = _get_kms_auth_data()
        except AuthenticationError:
            logger.exception('Failed to authenticate request.')
            return abort(403)
        if kms_auth_data:
            validator = _get_validator()
            _from = validator.extract_username_field(
                    kms_auth_data['username'],
                    'from',
            )
            _user_type = validator.extract_username_field(
                    kms_auth_data['username'],
                    'user_type',
            )
            try:
                if _user_type not in settings.KMS_AUTH_USER_TYPES:
                    msg = '{0} is not an allowed user type for KMS auth.'
                    msg = msg.format(_user_type)
                    logger.warning(msg)
                    return abort(403)
                with stats.timer('decrypt_token'):
                    token_data = validator.decrypt_token(
                        kms_auth_data['username'],
                        kms_auth_data['token']
                    )
                logger.debug(
                    'Auth request had the following token_data: {0}'.format(
                        token_data
                    )
                )
                msg = 'Authenticated {0} with user_type {1} via kms auth'
                msg = msg.format(_from, _user_type)
                logger.debug(msg)
                g.user_type = _user_type
                g.auth_type = 'kms'
                g.account = account_for_key_alias(token_data['key_alias'])
                g.username = _from
                return f(*args, **kwargs)
            except kmsauth.TokenValidationError:
                logger.exception('Failed to decrypt authentication token.')
                msg = 'Access denied for {0}. Authentication Failed.'
                msg = msg.format(_from)
                logger.warning(msg)
                return abort(403)

        # If not using kms auth, require auth using the user_mod authn module.
        else:
            user_type = 'user'

            if user_mod.is_expired():
                return abort(401)

            if user_mod.is_authenticated():
                try:
                    user_mod.check_authorization()
                except NotAuthorized as e:
                    logger.warning('Not authorized -- {}'.format(e))
                    return abort(403)
                else:
                    # User took an action, extend the expiration time.
                    user_mod.set_expiration()
                    # auth-N and auth-Z are good, call the decorated function
                    g.user_type = user_type
                    g.auth_type = user_mod.auth_type
                    # ensure that the csrf cookie value is set
                    resp = make_response(f(*args, **kwargs))
                    user_mod.set_csrf_token(resp)
                    return resp

            # Not authenticated
            return abort(401)

    return decorated


def require_logout_for_goodbye(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not settings.USE_AUTH:
            return f(*args, **kwargs)

        # ideally we would call check_csrf_token, but I don't think logout CSRF
        # is a serious concern for this application

        try:
            get_logged_in_user()
        except UserUnknownError:
            # ok, not logged in
            return f(*args, **kwargs)

        logger.warning('require_logout(): calling log_out()')
        resp = user_mod.log_out()

        if resp.headers.get('Location') == url_for('static_files.goodbye'):
            # avoid redirect loop and just render the page
            return f(*args, **kwargs)
        else:
            return resp

    return decorated
