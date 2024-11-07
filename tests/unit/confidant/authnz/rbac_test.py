from pytest_mock.plugin import MockerFixture

from confidant.app import create_app
from confidant.authnz import rbac


def test_default_acl(mocker: MockerFixture):
    mocker.patch('confidant.settings.USE_AUTH', True)
    app = create_app()
    with app.test_request_context('/fake'):
        g_mock = mocker.patch('confidant.authnz.g')

        # Test for user type is user
        g_mock.user_type = 'user'
        assert rbac.default_acl(resource_type='service') is True
        assert rbac.default_acl(resource_type='certificate') is False
        # Test for user type is service, but not an allowed resource type
        g_mock.user_type = 'service'
        g_mock.username = 'test-service'
        assert rbac.default_acl(
            resource_type='service',
            action='update',
            resource_id='test-service'
        ) is False
        # Test for user type is service, and an allowed resource, with metadata
        # action, but service name doesn't match
        g_mock.username = 'bad-service'
        assert rbac.default_acl(
            resource_type='service',
            action='metadata',
            resource_id='test-service',
        ) is False
        # Test for user type is service, and an allowed resource, with metadata
        # action
        g_mock.username = 'test-service'
        assert rbac.default_acl(
            resource_type='service',
            action='metadata',
            resource_id='test-service',
        ) is True
        # Test for user type is service, and an allowed resource, with get
        # action
        assert rbac.default_acl(
            resource_type='service',
            action='get',
            resource_id='test-service',
        ) is True
        # Test for user type is service, with certificate resource and get
        # action, with a CN that doesn't match the name pattern
        assert rbac.default_acl(
            resource_type='certificate',
            action='get',
            # missing domain name...
            resource_id='test-service',
            kwargs={'ca': 'development'},
        ) is False
        # Test for user type is service, with certificate resource and get
        # action, with a valid CN
        assert rbac.default_acl(
            resource_type='certificate',
            action='get',
            resource_id='test-service.example.com',
            kwargs={'ca': 'development'},
        ) is True
        # Test for user type is service, with certificate resource and get
        # action, with a valid CN, and valid SAN values
        assert rbac.default_acl(
            resource_type='certificate',
            action='get',
            resource_id='test-service.example.com',
            kwargs={
                'ca': 'development',
                'san': [
                    'test-service.internal.example.com',
                    'test-service.external.example.com',
                ],
            },
        ) is True
        # Test for user type is service, with certificate resource and get
        # action, with an invalid CN
        assert rbac.default_acl(
            resource_type='certificate',
            action='get',
            resource_id='bad-service.example.com',
            kwargs={'ca': 'development'},
        ) is False
        # Test for user type is service, with certificate resource and get
        # action, with a valid CN
        assert rbac.default_acl(
            resource_type='certificate',
            action='get',
            resource_id='test-service.example.com',
            kwargs={
                'ca': 'development',
                'san': ['test-service.sub.example.com'],
            },
        ) is True
        # Test for user type is service, and an allowed resource, with
        # disallowed fake action
        assert rbac.default_acl(resource_type='service', action='fake') is False
        # Test for bad user type
        g_mock.user_type = 'badtype'
        assert rbac.default_acl(resource_type='service', action='get') is False


def test_no_acl():
    app = create_app()
    with app.test_request_context('/fake'):
        assert rbac.no_acl(resource_type='service', action='update') is True
