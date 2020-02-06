import json

from confidant.app import create_app
from confidant.services import certificatemanager


def test_get_certificate(mocker):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_user_type',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.certificates.authnz.user_is_service',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/certificates/test.example.com',
        follow_redirects=False,
    )
    assert ret.status_code == 401

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
        '/v1/certificates/test.example.com',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.certificates.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager'
         '.issue_certificate_with_key'),
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
            'key': 'test_key',
        },
    )
    ret = app.test_client().get(
        '/v1/certificates/test.example.com',
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
    key = certificatemanager.generate_key()
    csr = certificatemanager.generate_csr(key, 'test.example.com')
    encoded_csr = certificatemanager.encode_csr(csr).decode('ascii')

    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    ret = app.test_client().post(
        '/v1/certificates',
        data=json.dumps({}),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 400

    ret = app.test_client().post(
        '/v1/certificates',
        data=json.dumps({'validity': 7}),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 400

    ret = app.test_client().post(
        '/v1/certificates',
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
    ret = app.test_client().post(
        '/v1/certificates',
        data=json.dumps({
            'csr': encoded_csr,
            'validity': 7,
        }),
        content_type='application/json',
        follow_redirects=False,
    )
    assert ret.status_code == 401

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
        '/v1/certificates',
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
        ('confidant.routes.certificates.certificatemanager'
         '.issue_certificate'),
        return_value='test-arn',
    )
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager'
         '.get_certificate_from_arn'),
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
        },
    )
    ret = app.test_client().post(
        '/v1/certificates',
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
        'key': None,
    }
