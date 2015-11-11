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

from confidant import app
from confidant import keymanager
from confidant import stats

authomatic_config = {
    'google': {
        'class_': oauth2.Google,
        'consumer_key': app.config['GOOGLE_OAUTH_CLIENT_ID'],
        'consumer_secret': app.config['GOOGLE_OAUTH_CONSUMER_SECRET'],
        'scope': [
            'https://www.googleapis.com/auth/userinfo.profile',
            'https://www.googleapis.com/auth/userinfo.email'
        ]
    }
}
_authomatic = Authomatic(
    authomatic_config,
    app.config['AUTHOMATIC_SALT']
)

if app.config.get('USERS_FILE'):
    with open(app.config.get('USERS_FILE'), 'r') as f:
        users = yaml.safe_load(f.read())
else:
    users = {}


PRIVILEGES = {
    'user': ['*'],
    'service': ['get_service']
}


def get_logged_in_user_email():
    '''
    Retrieve logged-in user's email that is stored in cache
    '''
    if not app.config.get('USE_AUTH'):
        return 'unauthenticated user'
    else:
        return session['google_oauth2']['email'].lower()


def user_in_role(role):
    if not app.config.get('USE_AUTH'):
        return True
    if role == g.auth_role:
        return True
    return False


def user_is_service(service):
    if not app.config.get('USE_AUTH'):
        return True
    if g.username == service:
        return True
    return False


def role_has_privilege(role, privilege):
    for _privilege in PRIVILEGES[role]:
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
    token = request.headers.get('X-XSRF-TOKEN')
    return safe_str_cmp(token, session.get('XSRF-TOKEN'))


def require_csrf_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if check_csrf_token():
            return f(*args, **kwargs)
        return abort(401)
    return decorated


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if not app.config.get('USE_AUTH'):
            return f(*args, **kwargs)

        auth = request.authorization
        headers = request.headers
        using_basic_kms_auth = (
            auth and
            auth.get('username') and
            auth.get('password') != ''
        )
        using_kms_auth = (
            'X-Auth-Token' in headers and
            'X-Auth-From' in headers
        )

        # User suppplied basic auth info
        if using_basic_kms_auth or using_kms_auth:
            if using_basic_kms_auth:
                _from = auth['username']
                token = auth['password']
            else:
                _from = headers['X-Auth-From']
                token = headers['X-Auth-Token']
            try:
                with stats.timer('decrypt_token'):
                    payload = keymanager.decrypt_token(
                        token,
                        _from
                    )
                logging.debug('Auth request had the following payload:'
                              ' {0}'.format(payload))
                role = 'service'
                msg = 'Authenticated {0} with role {1} via kms auth'
                msg = msg.format(_from, role)
                logging.debug(msg)
                if role_has_privilege(role, f.func_name):
                    g.auth_role = role
                    g.username = _from
                    return f(*args, **kwargs)
                else:
                    msg = '{0} is not authorized to access {1}.'
                    msg = msg.format(_from, f.func_name)
                    logging.warning(msg)
                    return abort(403)
            except keymanager.TokenDecryptionError:
                msg = 'Access denied for {0}. Authentication Failed.'
                msg = msg.format(_from)
                logging.warning(msg)
                return abort(403)
        # If not using kms auth, require google auth.
        else:
            role = 'user'
            if not role_has_privilege(role, f.func_name):
                return abort(403)
            if 'email' in session.get('google_oauth2', []):
                if (app.config['USERS_FILE'] and
                        get_logged_in_user_email() not in users):
                    msg = 'User not authorized: {0}'
                    logging.warning(msg.format(get_logged_in_user_email()))
                    return abort(403)
                else:
                    g.auth_role = role
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
                    g.auth_role = role
                    # TODO: find a way to save the angular args
                    # authomatic adds url params google auth has stripped the
                    # angular args anyway, so let's just redirect back to the
                    # index.
                    return redirect(url_for('index'))
            return response
        return abort(403)
    return decorated
