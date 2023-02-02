from confidant.app import create_app


def test_get_token_override_user(mocker):
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch('confidant.routes.jwks.jwt_mapping_check', return_value=True)
    mocker.patch('confidant.routes.identity.authnz.get_logged_in_user',
                 return_value='test')
    mock_get_jwt = mocker.patch('confidant.routes.jwks.jwk_manager.get_jwt',
                                return_value='some-jwt')
    app = create_app()
    ret = app.test_client().get(
        '/v1/jwks/token?environment=test&target_user=test-override',
        follow_redirects=False
    )
    mock_get_jwt.assert_called_with('test', {
        'user': 'test-override',
        'is_service': True,
    })
    assert ret.status_code == 200


def test_get_token_override_user_not_authorized(mocker):
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch('confidant.routes.jwks.jwt_mapping_check',
                 return_value=False)
    mocker.patch('confidant.routes.identity.authnz.get_logged_in_user',
                 return_value='test')
    app = create_app()
    ret = app.test_client().get(
        '/v1/jwks/token?environment=test&target_user=test-override',
        follow_redirects=False
    )
    assert ret.status_code == 403


def test_get_token_no_override(mocker):
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch('confidant.routes.jwks.jwt_mapping_check',
                 return_value=True)
    mocker.patch('confidant.routes.identity.authnz.get_logged_in_user',
                 return_value='test')
    mock_get_jwt = mocker.patch('confidant.routes.jwks.jwk_manager.get_jwt',
                                return_value='some-jwt')
    app = create_app()
    ret = app.test_client().get(
        '/v1/jwks/token?environment=test',
        follow_redirects=False
    )
    mock_get_jwt.assert_called_with('test', {
        'user': 'test',
        'is_service': True,
    })
    assert ret.status_code == 200
