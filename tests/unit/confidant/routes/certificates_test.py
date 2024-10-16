import json
from pytest_mock.plugin import MockerFixture

from confidant.app import create_app
from confidant.services.certificate_authority.certificateauthoritybase import (
    CertificateNotReadyError,
)
from confidant.services.certificate_authority.acmpca import (
    ACMPrivateCertificateAuthority,
)


def test_get_certificate(mocker: MockerFixture):
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
    ca_object = ACMPrivateCertificateAuthority('development')
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.get_ca'),
        return_value=ca_object,
    )
    issue_certificate_with_key_return_value = {
        'certificate': 'test_certificate',
        'certificate_chain': 'test_certificate_chain',
        'key': 'test_key',
    }
    mocker.patch(
        'confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority.issue_certificate_with_key',  # noqa: E501
        return_value=issue_certificate_with_key_return_value,
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
    mocker.patch(
        'confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority.issue_certificate_with_key',  # noqa: E501
        side_effect=CertificateNotReadyError(),
    )
    ret = app.test_client().get(
        '/v1/certificates/development/test.example.com',
        follow_redirects=False,
    )
    assert ret.status_code == 429
    assert ret.headers['Retry-After'] == '2'


def test_get_certificate_from_csr(mocker: MockerFixture):
    ca_object = ACMPrivateCertificateAuthority('development')
    key = ca_object.generate_key()
    csr = ca_object.generate_csr(key, 'test.example.com')
    pem_csr = ca_object.encode_csr(csr)

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

    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.get_ca'),
        return_value=ca_object,
    )
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
        data=json.dumps(
            {
                'csr': pem_csr,
                'validity': 7,
            }
        ),
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
        data=json.dumps(
            {
                'csr': pem_csr,
                'validity': 7,
            }
        ),
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
    mocker.patch(
        'confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority.issue_certificate',  # noqa: E501
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
        },
    )
    ret = app.test_client().post(
        '/v1/certificates/development',
        data=json.dumps(
            {
                'csr': pem_csr,
                'validity': 7,
            }
        ),
        content_type='application/json',
        follow_redirects=False,
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {
        'certificate': 'test_certificate',
        'certificate_chain': 'test_certificate_chain',
    }


def test_list_cas(mocker: MockerFixture):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
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
    cas = [
        {
            'ca': 'development',
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
            'tags': {'environment': 'development'},
        }
    ]
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.list_cas'),
        return_value=cas,
    )
    ret = app.test_client().get('/v1/cas', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {
        'cas': [
            {
                'ca': 'development',
                'certificate': 'test_certificate',
                'certificate_chain': 'test_certificate_chain',
                'tags': {'environment': 'development'},
            }
        ],
    }


def test_get_ca(mocker: MockerFixture):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
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
    ca_object = ACMPrivateCertificateAuthority('development')
    mocker.patch(
        ('confidant.routes.certificates.certificatemanager.get_ca'),
        return_value=ca_object,
    )
    mocker.patch(
        'confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority.get_certificate_authority_certificate',  # noqa: E501
        return_value={
            'ca': 'development',
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
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
        'tags': {'environment': 'development'},
    }
