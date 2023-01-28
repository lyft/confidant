import json
import pytest

from unittest import mock
from datetime import datetime

from confidant.app import create_app
from confidant.models.service import Service
from confidant.models.credential import Credential


@pytest.fixture()
def service(mocker):
    return Service(
        id='something-production-iad',
        data_type='service',
        credentials=['1234', '5678'],
        blind_credentials=set(),
        enabled=True,
        revision=1,
        modified_by='user'
    )


@pytest.fixture()
def credential_list(mocker):
    credentials = [
        Credential(
            id='1234',
            revision=1,
            data_type='credential',
            enabled=True,
            name='Test credential',
            credential_pairs='akjlaklkaj==',
            data_key='slkjlksfjklsdjf==',
            cipher_version=2,
            metadata={},
            modified_date=datetime.now(),
            modified_by='test@example.com',
            documentation='',
        ),
        Credential(
            id='5678',
            revision=2,
            data_type='credential',
            enabled=True,
            name='Test credential 2',
            credential_pairs='akjlaklkaj==',
            data_key='slkjlksfjklsdjf==',
            cipher_version=2,
            metadata={},
            modified_date=datetime.now(),
            modified_by='test@example.com',
            documentation='',
        ),
    ]
    return credentials


def test_get_services_list(mocker, service, credential_list):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.services.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.services.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/services/something-production-iad/credentials',
        follow_redirects=False
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.services.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.services.credentialmanager.Credential.batch_get',
        return_value=credential_list,
    )
    mocker.patch(
        'confidant.models.credential.'
        'Credential._get_decrypted_credential_pairs',
        return_value={},
    )
    mocker.patch(
        'confidant.models.service.Service.get',
        return_value=service,
    )
    ret = app.test_client().get(
        '/v1/services/something-production-iad/credentials',
        follow_redirects=False
    )
    cred_ids = ['1234', '5678']
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['credentials']) == len(cred_ids)
    assert json_data['next_page'] is None
    assert json_data['credentials'][0]['id'] in cred_ids
    assert json_data['credentials'][1]['id'] in cred_ids

    mocker.patch(
        'confidant.services.credentialmanager.Credential.batch_get',
        return_value=[credential_list[0]],
    )
    ret = app.test_client().get(
        '/v1/services/something-production-iad/credentials?limit=1',
        follow_redirects=False
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['credentials']) == 1

    mocker.patch(
        'confidant.services.credentialmanager.Credential.batch_get',
        return_value=[credential_list[1]],
    )
    ret = app.test_client().get(
        '/v1/services/something-production-iad/credentials?limit=1&page=2',
        follow_redirects=False
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['credentials']) == 1
