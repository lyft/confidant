import fnmatch
import yaml
import random
import logging

from authomatic import Authomatic
from authomatic.providers import oauth2
from authomatic.adapters import WerkzeugAdapter
from flask import abort, request,  make_response, session, g
from flask import redirect, url_for
from werkzeug.security import safe_str_cmp
from functools import wraps

from confidant import keymanager
from confidant.app import app
from confidant.utils import stats

authomatic_config = {
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

_authomatic = Authomatic(
    authomatic_config,
    app.config['AUTHOMATIC_SALT']
)

users = {}
if app.config['USERS_FILE']:
    with open(app.config.get('USERS_FILE'), 'r') as f:
        users = yaml.safe_load(f.read())

PRIVILEGES = {
    'user': ['*'],
    'service': ['get_service']
}


def get_logged_in_user():
    '''
    Retrieve logged-in user's email that is stored in cache
    '''
    if not app.config.get('USE_AUTH'):
        return 'unauthenticated user'
    if 'google_oauth2' in session:
        return session['google_oauth2']['email'].lower()
    if hasattr(g, 'username'):
        return g.username
    raise UserUnknownError()


def user_is_user_type(user_type):
    if not app.config.get('USE_AUTH'):
        return True
    if user_type == g.user_type:
        return True
    return False


def user_is_service(service):
    if not app.config.get('USE_AUTH'):
        return True
    if g.username == service:
        return True
    return False


def user_type_has_privilege(user_type, privilege):
    for _privilege in PRIVILEGES[user_type]:
        if fnmatch.fnmatch(privilege, _privilege):
            return True
    return False


def get_csrf_token():
    if 'XSRF-TOKEN' not in session:
        set_csrf_token()
    return session['XSRF-TOKEN']


def set_csrf_token():
    session['XSRF-TOKEN'] = '{0:x}'.format(
        random.SystemRandom().getrandbits(160)
    )


def check_csrf_token():
    # KMS is username/password or header auth, so we don't need to check for
    # csrf tokens.
    if g.auth_type == 'kms':
        return True
    token = request.headers.get('X-XSRF-TOKEN')
    return safe_str_cmp(token, session.get('XSRF-TOKEN'))


def require_csrf_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if check_csrf_token():
            return f(*args, **kwargs)
        return abort(401)
    return decorated


def _parse_username(username):
    username_arr = username.split('/')
    if len(username_arr) == 3:
        # V2 token format: version/service/myservice or version/user/myuser
        version = int(username_arr[0])
        user_type = username_arr[1]
        username = username_arr[2]
    elif len(username_arr) == 1:
        # Old format, specific to services: myservice
        version = 1
        username = username_arr[0]
        user_type = 'service'
    else:
        raise TokenVersionError('Unsupported username format.')
    return version, user_type, username


def _get_kms_auth_data():
    data = {}
    auth = request.authorization
    headers = request.headers
    if auth and auth.get('username'):
        if not auth.get('password'):
            raise AuthenticationError('No password provided via basic auth.')
        (data['version'],
         data['user_type'],
         data['from']) = _parse_username(auth['username'])
        data['token'] = auth['password']
    elif 'X-Auth-Token' in headers and 'X-Auth-From' in headers:
        if not headers.get('X-Auth-Token'):
            raise AuthenticationError(
                'No X-Auth-Token provided via auth headers.'
            )
        (data['version'],
         data['user_type'],
         data['from']) = _parse_username(headers['X-Auth-From'])
        data['token'] = headers['X-Auth-Token']
    return data


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not app.config.get('USE_AUTH'):
            return f(*args, **kwargs)

        # User suppplied basic auth info
        try:
            kms_auth_data = _get_kms_auth_data()
        except TokenVersionError:
            logging.warning('Invalid token version used.')
            return abort(403)
        except AuthenticationError:
            logging.exception('Failed to authenticate request.')
            return abort(403)
        if kms_auth_data:
            try:
                if (kms_auth_data['user_type']
                        not in app.config['KMS_AUTH_USER_TYPES']):
                    msg = '{0} is not an allowed user type for KMS auth.'
                    msg = msg.format(kms_auth_data['user_type'])
                    logging.warning(msg)
                    return abort(403)
                with stats.timer('decrypt_token'):
                    payload = keymanager.decrypt_token(
                        kms_auth_data['version'],
                        kms_auth_data['user_type'],
                        kms_auth_data['from'],
                        kms_auth_data['token']
                    )
                logging.debug('Auth request had the following payload:'
                              ' {0}'.format(payload))
                msg = 'Authenticated {0} with user_type {1} via kms auth'
                msg = msg.format(
                    kms_auth_data['from'],
                    kms_auth_data['user_type']
                )
                logging.debug(msg)
                if user_type_has_privilege(
                        kms_auth_data['user_type'],
                        f.func_name):
                    g.user_type = kms_auth_data['user_type']
                    g.auth_type = 'kms'
                    g.username = kms_auth_data['from']
                    return f(*args, **kwargs)
                else:
                    msg = '{0} is not authorized to access {1}.'
                    msg = msg.format(kms_auth_data['from'], f.func_name)
                    logging.warning(msg)
                    return abort(403)
            except keymanager.TokenDecryptionError:
                logging.exception('Failed to decrypt authentication token.')
                msg = 'Access denied for {0}. Authentication Failed.'
                msg = msg.format(kms_auth_data['from'])
                logging.warning(msg)
                return abort(403)
        # If not using kms auth, require google auth.
        else:
            user_type = 'user'
            if not user_type_has_privilege(user_type, f.func_name):
                return abort(403)
            if 'email' in session.get('google_oauth2', []):
                if (app.config['USERS_FILE'] and
                        get_logged_in_user() not in users):
                    msg = 'User not authorized: {0}'
                    logging.warning(msg.format(get_logged_in_user()))
                    return abort(403)
                else:
                    g.user_type = user_type
                    g.auth_type = 'oauth'
                    return f(*args, **kwargs)
            response = make_response()
            if request.is_secure:
                secure_cookie = True
            else:
                secure_cookie = False
            result = _authomatic.login(
                WerkzeugAdapter(request, response),
                'google',
                session=session,
                session_saver=lambda: app.save_session(session, response),
                secure_cookie=secure_cookie
            )
            if result:
                if result.error:
                    msg = 'Google auth failed with error: {0}'
                    logging.error(msg.format(result.error.message))
                    return abort(403)
                if result.user:
                    result.user.update()
                    user = result.user
                    email_suffix = app.config['GOOGLE_AUTH_EMAIL_SUFFIX']
                    if email_suffix and not user.email.endswith(email_suffix):
                        return abort(403)
                    session['google_oauth2'] = {}
                    session['google_oauth2']['email'] = user.email
                    session['google_oauth2']['first_name'] = user.first_name
                    session['google_oauth2']['last_name'] = user.last_name
                    g.user_type = user_type
                    g.auth_type = 'oauth'
                    # TODO: find a way to save the angular args
                    # authomatic adds url params google auth has stripped the
                    # angular args anyway, so let's just redirect back to the
                    # index.
                    return redirect(url_for('index'))
            return response
        return abort(403)
    return decorated


class UserUnknownError(Exception):
    pass


class TokenVersionError(Exception):
    pass


class AuthenticationError(Exception):
    pass
