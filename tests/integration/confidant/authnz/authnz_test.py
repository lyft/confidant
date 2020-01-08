import base64

from confidant.app import create_app
from confidant.authnz import userauth


def test_auth_redirect(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    app = create_app()
    app.debug = True
    ret = app.test_client().get('/', follow_redirects=False)
    assert ret.status_code == 302


def test_no_auth(mocker):
    mocker.patch('confidant.settings.USE_AUTH', False)
    app = create_app()
    app.debug = True
    user_mod = userauth.init_user_auth_class()
    mocker.patch('confidant.authnz.user_mod', user_mod)
    ret = app.test_client().get('/v1/user/email')
    assert ret.status_code == 200


def test_auth_failure(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    app = create_app()
    app.debug = True
    ret = app.test_client().get('/v1/user/email', follow_redirects=False)
    assert ret.status_code == 401


def test_auth_with_email_session_in_users(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    mocker.patch('confidant.settings.USER_EMAIL_SUFFIX', '')
    app = create_app()
    app.debug = True
    to_patch = ('confidant.authnz.userauth.AbstractUserAuthenticator.'
                'allowed_email_whitelist')
    mock_whitelist = mocker.patch(to_patch, new_callable=mocker.PropertyMock)
    mock_whitelist.return_value = ['example@example.com']
    with app.test_client() as c:
        with c.session_transaction() as session:
            session['user'] = {'email': 'example@example.com'}
        ret = c.get('/v1/user/email', follow_redirects=False)
        assert ret.status_code == 200


def test_auth_with_email_session_bad_prefix(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    # USERS_FILE needs to be set to test users file
    mocker.patch('confidant.settings.USERS_FILE', '')
    mocker.patch('confidant.settings.USER_EMAIL_SUFFIX', '@example.com')
    app = create_app()
    app.debug = True
    with app.test_client() as c:
        with c.session_transaction() as session:
            session['user'] = {'email': 'example@badexample.com'}
        ret = c.get('/v1/user/email', follow_redirects=False)
        assert ret.status_code == 403


def test_auth_with_email_session_not_in_users(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    # USERS_FILE needs to be set to test users file
    mocker.patch('confidant.settings.USERS_FILE', '')
    mocker.patch('confidant.settings.USER_EMAIL_SUFFIX', '')
    app = create_app()
    app.debug = True
    to_patch = ('confidant.authnz.userauth.AbstractUserAuthenticator.'
                'allowed_email_whitelist')
    mock_whitelist = mocker.patch(to_patch, new_callable=mocker.PropertyMock)
    mock_whitelist.return_value = ['example@example.com']
    with app.test_client() as c:
        with c.session_transaction() as session:
            session['user'] = {'email': 'baduser@example.com'}
        ret = c.get('/v1/user/email', follow_redirects=False)
        assert ret.status_code == 403


def test_auth_with_email_session(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    mocker.patch('confidant.settings.USERS_FILE', '')
    mocker.patch('confidant.settings.USER_EMAIL_SUFFIX', '')
    app = create_app()
    app.debug = True
    to_patch = ('confidant.authnz.userauth.AbstractUserAuthenticator.'
                'allowed_email_whitelist')
    mock_whitelist = mocker.patch(to_patch, new_callable=mocker.PropertyMock)
    mock_whitelist.return_value = None
    with app.test_client() as c:
        with c.session_transaction() as session:
            session['user'] = {'email': 'example@example.com'}
        ret = c.get('/v1/user/email', follow_redirects=False)
        assert ret.status_code == 200


def test_header_csrf(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    mocker.patch('confidant.settings.USER_AUTH_MODULE', 'header')
    mocker.patch(
        'confidant.settings.HEADER_AUTH_USERNAME_HEADER',
        'X-Confidant-User',
    )
    mocker.patch(
        'confidant.settings.HEADER_AUTH_EMAIL_HEADER',
        'X-Confidant-Email',
    )
    mocker.patch(
        'confidant.settings.XSRF_COOKIE_NAME',
        'XSRF-TOKEN',
    )
    app = create_app()
    app.debug = True
    user_mod = userauth.init_user_auth_class()
    mocker.patch('confidant.authnz.user_mod', user_mod)
    ret = app.test_client().get(
        '/v1/user/email',
        headers={
            "X-Confidant-User": "user",
            "X-Confidant-Email": "user@example.com",
        },
    )

    assert ret.status_code == 200

    def has_xsrf_cookie(headers):
        cookies = headers.get_all('Set-Cookie')
        for cookie in cookies:
            if cookie.startswith('XSRF-TOKEN='):
                return True
        return False

    assert has_xsrf_cookie(ret.headers) is True


def test_invalid_kms_auth_token(mocker):
    mocker.patch('confidant.settings.USE_AUTH', True)
    app = create_app()
    app.debug = True
    auth = base64.b64encode(b'confidant-development:faketoken').decode()
    ret = app.test_client().get(
        '/v1/services/confidant-development',
        headers={'Authorization': 'Basic {0}'.format(auth)},
        follow_redirects=False
    )
    assert ret.status_code == 403
