from confidant.authnz import rbac
from confidant.app import create_app


def test_default_acl(mocker):
    app = create_app()
    with app.test_request_context('/fake'):
        # Test for user type is user
        mocker.patch('confidant.authnz.user_is_user_type', return_value=True)
        assert rbac.default_acl(resource_type='service') is True
        # Test for user type is service, but not an allowed resource type
        mocker.patch(
            'confidant.authnz.user_is_user_type',
            side_effect=[False, True],
        )
        assert rbac.default_acl(
            resource_type='service', action='update'
        ) is False
        # Test for user type is service, and an allowed resource, with metadata
        # action, but service name doesn't match
        mocker.patch(
            'confidant.authnz.user_is_user_type',
            side_effect=[False, True],
        )
        mocker.patch(
            'confidant.authnz.user_is_service',
            return_value=False,
        )
        assert rbac.default_acl(
            resource_type='service', action='metadata'
        ) is False
        # Test for user type is service, and an allowed resource, with metadata
        # action
        mocker.patch(
            'confidant.authnz.user_is_user_type',
            side_effect=[False, True],
        )
        mocker.patch(
            'confidant.authnz.user_is_service',
            return_value=True,
        )
        assert rbac.default_acl(
            resource_type='service', action='metadata'
        ) is True
        # Test for user type is service, and an allowed resource, with get
        # action
        mocker.patch(
            'confidant.authnz.user_is_user_type',
            side_effect=[False, True],
        )
        assert rbac.default_acl(resource_type='service', action='get') is True
        # Test for user type is service, and an allowed resource, with
        # disallowed fake action
        mocker.patch(
            'confidant.authnz.user_is_user_type',
            side_effect=[False, True],
        )
        assert rbac.default_acl(resource_type='service', action='fake') is False
        # Test for bad user type
        mocker.patch(
            'confidant.authnz.user_is_user_type',
            side_effect=[False, False],
        )
        assert rbac.default_acl(resource_type='service', action='get') is False


def test_no_acl():
    app = create_app()
    with app.test_request_context('/fake'):
        assert rbac.no_acl(resource_type='service', action='update') is True
