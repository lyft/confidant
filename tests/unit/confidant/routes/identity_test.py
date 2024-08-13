from pytest_mock.plugin import MockerFixture
from typing import Union

from confidant.authnz import UserUnknownError
from confidant.app import create_app


def test_get_user_info(mocker: MockerFixture):
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.identity.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    app = create_app()
    ret = app.test_client().get('/v1/user/email', follow_redirects=False)
    assert ret.status_code == 200
    assert ret.json == {'email': 'test@example.com'}


def test_get_user_info_no_user(mocker: MockerFixture):
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.identity.authnz.get_logged_in_user',
        side_effect=UserUnknownError(),
    )
    app = create_app()
    ret = app.test_client().get('/v1/user/email', follow_redirects=False)
    assert ret.status_code == 200
    assert ret.json == {'email': None}


def test_get_client_config(mocker: MockerFixture):
    def acl_module_check(resource_type: str, action: str) -> Union[bool, None]:
        if resource_type == 'credential':
            if action == 'create':
                return False
            elif action == 'list':
                return True
        elif resource_type == 'service':
            if action == 'create':
                return True
            elif action == 'list':
                return False
        return None

    mocker.patch('confidant.routes.identity.acl_module_check', acl_module_check)
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch('confidant.settings.CLIENT_CONFIG', {'test': 'client_config'})
    mocker.patch('confidant.settings.KMS_AUTH_MANAGE_GRANTS', False)
    mocker.patch(
        'confidant.settings.SCOPED_AUTH_KEYS',
        {'sandbox-account': 'sandbox'},
    )
    mocker.patch('confidant.settings.XSRF_COOKIE_NAME', 'CSRF_TOKEN')
    mocker.patch('confidant.settings.MAINTENANCE_MODE', True)
    mocker.patch('confidant.settings.HISTORY_PAGE_LIMIT', 50)

    expected = {
        'defined': {'test': 'client_config'},
        'generated': {
            'kms_auth_manage_grants': False,
            'aws_accounts': ['sandbox'],
            'xsrf_cookie_name': 'CSRF_TOKEN',
            'maintenance_mode': True,
            'history_page_limit': 50,
            'defined_tags': ['ROTATION_EXCLUDED', 'FINANCIALLY_SENSITIVE'],
            'permissions': {
                'credentials': {
                    'list': True,
                    'create': False,
                },
                'blind_credentials': {
                    'list': True,
                    'create': True,
                },
                'services': {
                    'list': False,
                    'create': True,
                },
            },
        },
    }

    app = create_app()
    ret = app.test_client().get('/v1/client_config', follow_redirects=False)
    assert ret.status_code == 200
    assert ret.json == expected
