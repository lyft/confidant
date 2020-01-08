import pytest
from werkzeug.exceptions import Unauthorized

from confidant.app import create_app
from confidant import authnz


@pytest.fixture(autouse=True)
def mock_email_suffix(mocker):
    mocker.patch('confidant.authnz.settings.USER_EMAIL_SUFFIX', '')


def test_get_logged_in_user(mocker):
    mocker.patch('confidant.authnz.settings.USER_EMAIL_SUFFIX', 'example.com')
    app = create_app()
    with app.test_request_context('/v1/user/email'):
        with pytest.raises(authnz.UserUnknownError):
            authnz.get_logged_in_user()
        g_mock = mocker.patch('confidant.authnz.g')
        g_mock.username = 'unittestuser'
        assert authnz.get_logged_in_user() == 'unittestuser'


def test_get_logged_in_user_from_session(mocker):
    mocker.patch('confidant.authnz.settings.USER_EMAIL_SUFFIX', 'example.com')
    app = create_app()
    with app.test_request_context('/v1/user/email'):
        session_data = {
            'user': {'email': 'unittestuser@example.com'}
        }
        mocker.patch('confidant.authnz.userauth.session', session_data)
        assert authnz.get_logged_in_user() == 'unittestuser@example.com'


def test_user_is_user_type(mocker):
    mocker.patch('confidant.authnz.settings.USE_AUTH', False)
    assert authnz.user_is_user_type('anything') is True

    mocker.patch('confidant.authnz.settings.USE_AUTH', True)
    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.user_type = 'user'
    assert authnz.user_is_user_type('user') is True

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.user_type = 'service'
    assert authnz.user_is_user_type('service') is True

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.user_type = 'user'
    assert authnz.user_is_user_type('service') is False

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.user_type = 'service'
    assert authnz.user_is_user_type('user') is False


def test_user_type_has_privilege():
    assert authnz.user_type_has_privilege('user', 'random_function') is True
    assert authnz.user_type_has_privilege('service', 'random_function') is False
    assert authnz.user_type_has_privilege('service', 'get_service') is True


def test_require_csrf_token(mocker):
    mock_fn = mocker.Mock()
    mock_fn.__name__ = 'mock_fn'
    mock_fn.return_value = 'unittestval'

    wrapped = authnz.require_csrf_token(mock_fn)

    mocker.patch('confidant.authnz.settings.USE_AUTH', False)
    assert wrapped() == 'unittestval'

    mocker.patch('confidant.authnz.settings.USE_AUTH', True)
    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.auth_type = 'kms'
    assert wrapped() == 'unittestval'

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.auth_type = 'google oauth'
    u_mock = mocker.patch('confidant.authnz.user_mod')
    u_mock.check_csrf_token = mocker.Mock(return_value=True)
    assert wrapped() == 'unittestval'

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.auth_type = 'google oauth'
    u_mock = mocker.patch('confidant.authnz.user_mod')
    u_mock.check_csrf_token = mocker.Mock(return_value=False)
    with pytest.raises(Unauthorized):
        wrapped()


def test_user_is_service(mocker):
    mocker.patch('confidant.authnz.settings.USE_AUTH', False)
    assert authnz.user_is_service('anything') is True

    mocker.patch('confidant.authnz.settings.USE_AUTH', True)
    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.username = 'confidant-unitttest'
    assert authnz.user_is_service('confidant-unitttest') is True

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.username = 'confidant-unitttest'
    assert authnz.user_is_service('notconfidant-unitttest') is False


def test_redirect_to_logout_if_no_auth(mocker):
    mock_fn = mocker.Mock()
    mock_fn.__name__ = 'mock_fn'
    mock_fn.return_value = 'unittestval'

    wrapped = authnz.redirect_to_logout_if_no_auth(mock_fn)

    u_mock = mocker.patch('confidant.authnz.user_mod')
    u_mock.is_expired = mocker.Mock(return_value=False)
    u_mock.is_authenticated = mocker.Mock(return_value=True)
    assert wrapped() == 'unittestval'

    u_mock = mocker.patch('confidant.authnz.user_mod')
    u_mock.is_expired = mocker.Mock(return_value=True)
    u_mock.redirect_to_goodbye = mocker.Mock(return_value='redirect_return')
    assert wrapped() == 'redirect_return'

    u_mock = mocker.patch('confidant.authnz.user_mod')
    u_mock.is_expired = mocker.Mock(return_value=False)
    u_mock.is_authenticated = mocker.Mock(return_value=False)
    u_mock.redirect_to_goodbye = mocker.Mock(return_value='redirect_return')
    assert wrapped() == 'redirect_return'


@pytest.fixture()
def mock_header_auth(mocker):
    mocker.patch('confidant.authnz.settings.USE_AUTH', True)
    mocker.patch('confidant.authnz.settings.USER_AUTH_MODULE', 'header')
    mocker.patch(
        'confidant.authnz.settings.HEADER_AUTH_USERNAME_HEADER',
        'X-Confidant-Username'
    )
    mocker.patch(
        'confidant.authnz.settings.HEADER_AUTH_EMAIL_HEADER',
        'X-Confidant-Email'
    )
    mocker.patch(
        'confidant.authnz.user_mod',
        authnz.userauth.init_user_auth_class()
    )


def test_header_auth_will_extract_from_request(mocker, mock_header_auth):
    app = create_app()
    with app.test_request_context('/fake'):
        # No headers given: an error
        with pytest.raises(authnz.UserUnknownError):
            authnz.get_logged_in_user()

        # Both headers given: success
        request_mock = mocker.patch('confidant.authnz.userauth.request')
        request_mock.headers = {
            'X-Confidant-Username': 'unittestuser',
            'X-Confidant-Email': 'unittestuser@example.com',  # noqa:E501
        }
        assert authnz.get_logged_in_user() == 'unittestuser@example.com'


def test_header_auth_will_log_in(mocker, mock_header_auth):
    app = create_app()
    with app.test_request_context('/fake'):
        request_mock = mocker.patch('confidant.authnz.userauth.request')
        request_mock.headers = {
            'X-Confidant-Username': 'unittestuser',
            'X-Confidant-Email': 'unittestuser@example.com',  # noqa:E501
        }
        resp = authnz.user_mod.log_in()

        assert resp.status_code == 302
        assert resp.headers['Location'] == '/'
