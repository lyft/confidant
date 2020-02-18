import json

from confidant.app import create_app
from confidant.services import certificatemanager


def test_get_certificate(mocker):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.authnz.get_logged_in_user',
        return_value='badservice',
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_user_type',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_service',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/certificates/development/test.example.com',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_user_type',
        return_value=False,
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/certificates/development/test.example.com',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=True,
    )
    mocker.patch('confidant.authnz.get_logged_in_user', return_value='test')
    ca_object = certificatemanager.CertificateAuthority('development')
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.get_ca'),
        return_value=ca_object,
    )
    ca_object.issue_certificate_with_key = mocker.Mock(
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
            'key': 'test_key',
        },
    )
    ret = app.test_client().get(
        '/v1/certificates/development/test.example.com',
        follow_redirects=False,
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {
        'certificate': 'test_certificate',
        'certificate_chain': 'test_certificate_chain',
        'key': 'test_key',
    }


def test_get_certificate_from_csr(mocker):
    ca_object = certificatemanager.CertificateAuthority('development')
    key = ca_object.generate_key()
    csr = ca_object.generate_csr(key, 'test.example.com')
    encoded_csr = ca_object.encode_csr(csr).decode('ascii')

    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps({}),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 400

    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps({'validity': 7}),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 400

    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps({'csr': 'invalid_csr'}),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 400

    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_user_type',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_service',
        return_value=False,
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.get_logged_in_user',
        return_value='badservice',
    )
    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps({
            'csr': encoded_csr,
            'validity': 7,
        }),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_user_type',
        return_value=False,
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps({
            'csr': encoded_csr,
            'validity': 7,
        }),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.get_ca'),
        return_value=ca_object,
    )
    ca_object.issue_certificate = mocker.Mock(
        return_value='test-certificate-arn',
    )
    ca_object.get_certificate_from_arn = mocker.Mock(
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
        },
    )
    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps({
            'csr': encoded_csr,
            'validity': 7,
        }),
        content_type='application/json',
        follow_redirects=False,
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {
        'certificate': 'test_certificate',
        'certificate_chain': 'test_certificate_chain',
    }


def test_list_cas(mocker):
    app = create_app()

    mocker.patch(
        'confidant.routes.certificates.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/cas',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=True,
    )
    mocker.patch('confidant.authnz.get_logged_in_user', return_value='test')
    ca_object = certificatemanager.CertificateAuthority('development')
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.list_cas'),
        return_value=[ca_object],
    )
    ca_object.issue_certificate_with_key = mocker.Mock(
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
            'key': 'test_key',
            'tags': {'environment': 'development'},
        },
    )
    ret = app.test_client().get('/v1/cas', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {
        'cas': [{
            'ca': 'development',
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
            'key': 'test_key',
            'tags': {'environment': 'development'},
        }],
    }


def test_get_ca(mocker):
    app = create_app()

    mocker.patch(
        'confidant.routes.certificates.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/cas',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=True,
    )
    mocker.patch('confidant.authnz.get_logged_in_user', return_value='test')
    ca_object = certificatemanager.CertificateAuthority('development')
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.get_ca'),
        return_value=ca_object,
    )
    ca_object.issue_certificate_with_key = mocker.Mock(
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
            'key': 'test_key',
            'tags': {'environment': 'development'},
        },
    )
    ret = app.test_client().get('/v1/cas/development', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {
        'ca': 'development',
        'certificate': 'test_certificate',
        'certificate_chain': 'test_certificate_chain',
        'key': 'test_key',
        'tags': {'environment': 'development'},
    }
