import pytest
from werkzeug.exceptions import Forbidden, Unauthorized

from confidant import authnz
from confidant.app import create_app


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


def test_service_in_account(mocker):
    # If we aren't scoping, this should pass
    assert authnz.service_in_account(None) is True

    g_mock = mocker.patch('confidant.authnz.g')
    g_mock.account = 'confidant-unitttest'
    assert authnz.service_in_account('bad-service') is False
    assert authnz.service_in_account('confidant-unitttest') is True


def test_account_for_key_alias(mocker):
    mocker.patch(
        'confidant.authnz.settings.SCOPED_AUTH_KEYS',
        {'sandbox-auth-key': 'sandbox'},
    )
    assert authnz.account_for_key_alias('sandbox-auth-key') == 'sandbox'
    assert authnz.account_for_key_alias('non-existent') is None


def test__get_kms_auth_data_from_auth(mocker):
    auth_mock = mocker.patch('confidant.authnz.request')
    expected = {
        'username': 'test-user',
        'token': 'test-token',
    }
    auth_mock.authorization = {
        'username': expected['username'],
        'password': expected['token'],
    }
    auth_mock.headers = None
    assert authnz._get_kms_auth_data() == expected

    auth_mock.authorization = {
        'username': expected['username'],
    }
    with pytest.raises(authnz.AuthenticationError):
        authnz._get_kms_auth_data()


def test__get_kms_auth_data_from_headers(mocker):
    auth_mock = mocker.patch('confidant.authnz.request')
    expected = {
        'username': 'test-user',
        'token': 'test-token',
    }
    auth_mock.headers = {
        'X-Auth-From': expected['username'],
        'X-Auth-Token': expected['token'],
    }
    auth_mock.authorization = None
    assert authnz._get_kms_auth_data() == expected

    auth_mock.headers = {
        'X-Auth-From': expected['username'],
        'X-Auth-Token': None,
    }
    with pytest.raises(authnz.AuthenticationError):
        authnz._get_kms_auth_data()


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


def test_require_auth(mocker):
    mocker.patch(
        'confidant.authnz.settings.KMS_AUTH_USER_TYPES',
        ['user', 'service'],
    )

    mock_fn = mocker.Mock()
    mock_fn.__name__ = 'mock_fn'
    mock_fn.return_value = 'unittestval'

    # Auth is disabled, so immediate return
    wrapped = authnz.require_auth(mock_fn)
    mocker.patch('confidant.authnz.settings.USE_AUTH', False)
    assert wrapped() == 'unittestval'

    # Test auth failure
    mocker.patch('confidant.authnz.settings.USE_AUTH', True)
    mocker.patch(
        'confidant.authnz._get_kms_auth_data',
        mocker.Mock(side_effect=authnz.AuthenticationError()),
    )
    with pytest.raises(Forbidden):
        wrapped()

    def extract_username_field(username, field):
        username_arr = username.split('/')
        if field == 'from':
            return username_arr[2]
        elif field == 'user_type':
            return username_arr[1]

    validator_mock = mocker.MagicMock()
    mocker.patch('confidant.authnz._get_validator', return_value=validator_mock)
    validator_mock.extract_username_field = extract_username_field

    # Test for a bad user type in the token
    mocker.patch(
        'confidant.authnz._get_kms_auth_data',
        return_value={
            'username': '2/badusertype/test-user',
            'token': 'test-token',
        },
    )
    with pytest.raises(Forbidden):
        wrapped()

    # Test for validation error from the kmsauth library
    mocker.patch(
        'confidant.authnz._get_kms_auth_data',
        return_value={
            'username': '2/service/test-user',
            'token': 'test-token',
        },
    )
    validator_mock.decrypt_token = mocker.Mock(
        side_effect=authnz.kmsauth.TokenValidationError
    )
    with pytest.raises(Forbidden):
        wrapped()

    validator_mock.decrypt_token = mocker.Mock(
        return_value={'payload': {}, 'key_alias': 'testkey'},
    )

    mocker.patch('confidant.authnz.account_for_key_alias', return_value=None)

    g_mock = mocker.patch('confidant.authnz.g')
    assert wrapped() == 'unittestval'
    assert g_mock.user_type == 'service'
    assert g_mock.auth_type == 'kms'
    assert g_mock.username == 'test-user'

    # User auth
    mocker.patch(
        'confidant.authnz._get_kms_auth_data',
        return_value={},
    )

    # Session token is expired
    user_mod = mocker.MagicMock()
    mocker.patch('confidant.authnz.user_mod', user_mod)
    user_mod.is_expired = mocker.Mock(return_value=True)
    with pytest.raises(Unauthorized):
        wrapped()

    # Failed to authenticate
    user_mod.is_expired = mocker.Mock(return_value=False)
    user_mod.is_authenticated = mocker.Mock(return_value=False)
    with pytest.raises(Unauthorized):
        wrapped()

    # User authentication success
    user_mod.is_authenticated = mocker.Mock(return_value=True)
    user_mod.check_authorization = mocker.Mock(return_value=None)
    user_mod.auth_type = 'testmod'
    user_mod.set_expiration = mocker.Mock()
    response = mocker.Mock()
    mocker.patch('confidant.authnz.make_response', return_value=response)
    user_mod.set_csrf_token = mocker.Mock()
    assert wrapped() == response
    assert g_mock.user_type == 'user'
    assert g_mock.auth_type == 'testmod'

    # User is authenticated, but not authorized
    user_mod.check_authorization = mocker.Mock(side_effect=authnz.NotAuthorized)
    with pytest.raises(Forbidden):
        wrapped()


def test_require_logout_for_goodbye(mocker):
    mock_fn = mocker.Mock()
    mock_fn.__name__ = 'mock_fn'
    mock_fn.return_value = 'unittestval'

    wrapped = authnz.require_logout_for_goodbye(mock_fn)

    mocker.patch('confidant.authnz.settings.USE_AUTH', False)
    assert wrapped() == 'unittestval'

    mocker.patch('confidant.authnz.settings.USE_AUTH', True)
    u_mock = mocker.patch('confidant.authnz.user_mod')
    mocker.patch(
        'confidant.authnz.get_logged_in_user',
        mocker.Mock(side_effect=authnz.UserUnknownError()),
    )
    assert wrapped() == 'unittestval'

    mocker.patch(
        'confidant.authnz.get_logged_in_user',
        mocker.Mock(return_value=True),
    )
    response = mocker.MagicMock()
    response.headers = {'Location': 'http://example.com'}
    u_mock.log_out = mocker.Mock(return_value=response)
    mocker.patch(
        'confidant.authnz.url_for',
        return_value='http://bad.example.com',
    )
    assert wrapped() == response
    mocker.patch('confidant.authnz.url_for', return_value='http://example.com')
    assert wrapped() == 'unittestval'
