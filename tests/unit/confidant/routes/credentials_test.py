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
def archive_credential(mocker):
    return Credential(
        id='123-1',
        revision=1,
        data_type='archive-credential',
        enabled=True,
        name='Archive credential',
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

    credential.id = '9012'
    ret = app.test_client().get('/v1/credentials/3456', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data['permissions']['update'] is True

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


def test_create_credential(mocker, credential):
    app = create_app()
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )

    # Bad ACL check
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().post(
        '/v1/credentials',
    )
    assert ret.status_code == 403

    # Bad request - required fields not present
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.credentials.Credential.data_type_date_index.query',
        return_value=credential,
    )
    mocker.patch(
        'confidant.routes.credentials.settings.ENFORCE_DOCUMENTATION',
        True,
    )
    ret = app.test_client().post(
        '/v1/credentials',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({'name': 'me'}),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 400
    assert 'documentation is a required field' == json_data['error']

    # Credential name already exists (ie: query returns a value)
    mocker.patch(
        'confidant.routes.credentials.Credential.data_type_date_index.query',
        return_value=[credential],
    )
    ret = app.test_client().post(
        '/v1/credentials',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'name': 'me',
            'documentation': 'doc',
            'credential_pairs': {'key': 'value'},
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 409
    assert 'Name already exists' in json_data['error']

    # All good
    mocker.patch(
        ('confidant.routes.credentials.Credential'
         '.data_type_date_index.query'),
        return_value=[],
    )
    mocker.patch(
        'confidant.routes.credentials.keymanager.create_datakey',
        return_value={'plaintext': '123', 'ciphertext': '888'},
    )
    mock_save = mocker.patch('confidant.routes.credentials.Credential.save')
    mocker.patch('confidant.routes.credentials.graphite.send_event')
    mocker.patch('confidant.routes.credentials.webhook.send_event')
    mocker.patch(
        ('confidant.routes.credentials.Credential'
         '._get_decrypted_credential_pairs'),
        return_value={'test': 'me'},
    )
    mocker.patch(
        'confidant.routes.credentials.CipherManager.encrypt',
        return_value={'foo': 'baz'}
    )
    ret = app.test_client().post(
        '/v1/credentials',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'documentation': 'doc',
            'credential_pairs': {'key': 'value'},
            'name': 'shiny new key',
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert 'shiny new key' == json_data['name']
    assert mock_save.call_count == 2


def test_update_credential(mocker, credential):
    app = create_app()
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )

    # Bad ACL check
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
        headers={"Content-Type": 'application/json'},
        data='{}',
    )
    assert ret.status_code == 403

    # Credential not found
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=DoesNotExist(),
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'enabled': 123,
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 404
    assert 'Credential not found.' == json_data['error']

    # Bad Request
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        return_value=credential,
    )
    mocker.patch(
        ('confidant.routes.credentials.credentialmanager'
         '.get_latest_credential_revision'),
        return_value=12,
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'enabled': 123,
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 400
    assert 'Enabled must be a boolean.' == json_data['error']

    # Credential conflicts with another service
    mocker.patch(
        'confidant.routes.credentials.keymanager.create_datakey',
        return_value={'plaintext': '123', 'ciphertext': '888'},
    )
    mocker.patch(
        ('confidant.routes.credentials.Credential'
         '._get_decrypted_credential_pairs'),
        return_value={'test': 'me'},
    )
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.get_services_for_credential'),
        return_value=[],
    )
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.pair_key_conflicts_for_services'),
        return_value={'123': {'services': ['service1']}},
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'credential_pairs': {'foo': 'baz'},
            'enabled': True,
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 400
    assert 'Conflicting key pairs in mapped service.' == json_data['error']

    # All good
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.pair_key_conflicts_for_services'),
        return_value={},
    )
    mock_save = mocker.patch('confidant.routes.credentials.Credential.save')
    mocker.patch('confidant.routes.credentials.graphite.send_event')
    mocker.patch('confidant.routes.credentials.webhook.send_event')
    mocker.patch(
        'confidant.routes.credentials.CipherManager.encrypt',
        return_value={'foo': 'baz'}
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'enabled': True,
            'credential_pairs': {'key': 'value'},
            'name': 'shiny new name',
            'documentation': 'doc',
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert 'shiny new name' == json_data['name']
    assert mock_save.call_count == 2


def test_revise_credential(mocker, credential, archive_credential):
    app = create_app()
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )

    # Bad ACL check
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    ret = app.test_client().put(
        '/v1/credentials/123/10',
        headers={"Content-Type": 'application/json'},
        data='{}',
    )
    assert ret.status_code == 403

    # Credential not found
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=DoesNotExist(),
    )
    ret = app.test_client().put(
        '/v1/credentials/123/10',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'enabled': 123,
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 404
    assert 'Credential not found.' == json_data['error']

    # Revert revision not an archive credential
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        return_value=credential,
    )
    mocker.patch(
        ('confidant.routes.credentials.credentialmanager'
         '.get_latest_credential_revision'),
        return_value=12,
    )
    ret = app.test_client().put(
        '/v1/credentials/123/10',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'enabled': 123,
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 400
    assert 'id provided is not a credential.' == json_data['error']

    # Revert conflicts with another service
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=[credential, archive_credential],
    )
    mocker.patch(
        'confidant.routes.credentials.keymanager.create_datakey',
        return_value={'plaintext': '123', 'ciphertext': '888'},
    )
    mocker.patch(
        ('confidant.routes.credentials.Credential'
         '._get_decrypted_credential_pairs'),
        return_value={'test': 'me'},
    )
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.get_services_for_credential'),
        return_value=[],
    )
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.pair_key_conflicts_for_services'),
        return_value={'123': {'services': ['service1']}},
    )
    ret = app.test_client().put(
        '/v1/credentials/123/10',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({}),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 400
    assert 'Conflicting key pairs in mapped service.' == json_data['error']

    # All good
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=[credential, archive_credential],
    )
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.pair_key_conflicts_for_services'),
        return_value={},
    )
    mock_save = mocker.patch('confidant.routes.credentials.Credential.save')
    mocker.patch('confidant.routes.credentials.graphite.send_event')
    mocker.patch('confidant.routes.credentials.webhook.send_event')
    mocker.patch(
        'confidant.routes.credentials.CipherManager.encrypt',
        return_value={'foo': 'baz'}
    )
    ret = app.test_client().put(
        '/v1/credentials/123/10',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({}),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert 'Archive credential' == json_data['name']
    assert mock_save.call_count == 2
