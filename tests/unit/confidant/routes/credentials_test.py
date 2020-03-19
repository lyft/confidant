import json
from datetime import datetime

import pytest
from pynamodb.exceptions import DoesNotExist

from confidant.app import create_app
from confidant.models.credential import Credential


@pytest.fixture()
def credential(mocker):
    return Credential(
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


def test_get_credential_list(mocker, credential_list):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get('/v1/credentials', follow_redirects=False)
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.models.credential.Credential.data_type_date_index.query',
        return_value=credential_list,
    )
    ret = app.test_client().get('/v1/credentials', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['credentials']) == len(credential_list)
    assert json_data['next_page'] is None


def test_get_credential(mocker, credential):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch('confidant.settings.ENABLE_SAVE_LAST_DECRYPTION_TIME', True)
    mock_save = mocker.patch.object(Credential, 'save', return_value=None)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get('/v1/credentials/1234', follow_redirects=False)
    assert ret.status_code == 403

    def acl_module_check(resource_type, action, resource_id):
        if action == 'metadata':
            if resource_id == '5678':
                return False
            else:
                return True
        elif action == 'get':
            if resource_id == '9012':
                return False
            else:
                return True
        elif action == 'update':
            if resource_id == '3456':
                return True
            else:
                return False

    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        acl_module_check,
    )
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        return_value=credential,
    )
    mocker.patch(
        ('confidant.routes.credentials.Credential'
         '._get_decrypted_credential_pairs'),
        return_value={'test': 'me'},
    )
    ret = app.test_client().get('/v1/credentials/1234', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data['permissions']['update'] is False

    credential.data_type = 'service'
    ret = app.test_client().get('/v1/credentials/1234', follow_redirects=False)
    assert ret.status_code == 404

    credential.data_type = 'credential'
    credential.id = '5678'
    ret = app.test_client().get('/v1/credentials/5678', follow_redirects=False)
    assert ret.status_code == 403

    credential.data_type = 'credential'
    credential.id = '9012'
    ret = app.test_client().get('/v1/credentials/5678', follow_redirects=False)
    assert ret.status_code == 403

    # Make sure credential is saved when ENABLE_SAVE_LAST_DECRYPTION_TIME=True
    # and metadata_only=False
    credential.id = '9012'
    ret = app.test_client().get(
        '/v1/credentials/3456?metadata_only=false',
        follow_redirects=False
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data['permissions']['update'] is True
    assert mock_save.call_count == 1

    # Make sure credential is NOT saved when
    # ENABLE_SAVE_LAST_DECRYPTION_TIME=True and metadata_only=True
    mock_save = mocker.patch.object(Credential, 'save', return_value=None)
    ret = app.test_client().get(
        '/v1/credentials/3456?metadata_only=true',
        follow_redirects=False
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data['permissions']['update'] is True
    assert mock_save.call_count == 0

    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=DoesNotExist(),
    )
    ret = app.test_client().get(
        '/v1/credentials/1234',
        follow_redirects=False,
    )
    assert ret.status_code == 404


def test_diff_credential(mocker, credential):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().get(
        '/v1/credentials/1234/1/2',
        follow_redirects=False,
    )
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        return_value=credential,
    )
    mocker.patch(
        ('confidant.routes.credentials.Credential'
         '._get_decrypted_credential_pairs'),
        return_value={'test': 'me'},
    )
    ret = app.test_client().get(
        '/v1/credentials/1234/1/2',
        follow_redirects=False,
    )
    assert ret.status_code == 400

    credential.data_type = 'archive-credential'
    ret = app.test_client().get(
        '/v1/credentials/1234/1/2',
        follow_redirects=False,
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data == {}

    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=DoesNotExist(),
    )
    ret = app.test_client().get(
        '/v1/credentials/1234/1/2',
        follow_redirects=False,
    )
    assert ret.status_code == 404

    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=[credential, DoesNotExist()],
    )
    ret = app.test_client().get(
        '/v1/credentials/1234/1/2',
        follow_redirects=False,
    )
    assert ret.status_code == 404
