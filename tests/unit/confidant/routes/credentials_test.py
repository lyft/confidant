import json
import pytz
from datetime import datetime
from pytest_mock.plugin import MockerFixture
from typing import List, Union

import pytest
from unittest import mock
from pynamodb.exceptions import DoesNotExist

from confidant.app import create_app
from confidant.models.credential import Credential


@pytest.fixture()
def credential(mocker: MockerFixture) -> Credential:
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
        last_rotation_date=datetime(2020, 1, 1, tzinfo=pytz.utc),
    )


@pytest.fixture()
def archive_credential(mocker: MockerFixture) -> Credential:
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
        tags=['OLD TAG'],
    )


@pytest.fixture()
def credential_list(mocker: MockerFixture) -> List[Credential]:
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


def test_get_credential_list(
    mocker: MockerFixture,
    credential_list: List[Credential]
):
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

    # test with pagination
    mock_credential_list = mock.Mock()
    mock_credential_list.__iter__ = mock.Mock(
        return_value=iter([credential_list[0]])
    )
    mock_credential_list.last_evaluated_key.return_value = {
        'something': 'test'
    }
    mocker.patch(
        'confidant.schema.credentials.encode_last_evaluated_key',
        return_value='{"something":"test"}',
    )
    mocker.patch(
        'confidant.models.credential.Credential.data_type_date_index.query',
        return_value=mock_credential_list,
    )
    ret = app.test_client().get(
        '/v1/credentials?limit=1',
        follow_redirects=False,
    )
    json_data = json.loads(ret.data)
    next_page = json_data['next_page']
    assert ret.status_code == 200
    assert len(json_data['credentials']) == 1
    assert next_page == '{"something":"test"}'

    # test second page
    mock_credential_list.__iter__ = mock.Mock(
        return_value=iter([credential_list[1]])
    )
    mock_credential_list.last_evaluated_key.return_value = None
    mocker.patch(
        'confidant.schema.credentials.encode_last_evaluated_key',
        return_value=None,
    )
    mocker.patch(
        'confidant.models.credential.Credential.data_type_date_index.query',
        return_value=mock_credential_list,
    )
    mocker.patch(
        'confidant.routes.credentials.decode_last_evaluated_key',
        return_value='{"something":"test"}',
    )
    ret = app.test_client().get(
        f'/v1/credentials?limit=1&page={next_page}',
        follow_redirects=False,
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['credentials']) == 1
    assert json_data['next_page'] is None


def test_get_credential(mocker: MockerFixture, credential: Credential):
    app = create_app()

    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch('confidant.settings.ENABLE_SAVE_LAST_DECRYPTION_TIME', True)
    mocker.patch.object(Credential, 'save', return_value=None)
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

    def acl_module_check(
            resource_type: str,
            action: str,
            resource_id: int) -> Union[bool, None]:
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
        return None

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
    credential.last_rotation_date = datetime(2020, 1, 1, tzinfo=pytz.UTC)
    mock_save = mocker.patch.object(Credential, 'save', return_value=None)
    credential.id = '9012'
    ret = app.test_client().get(
        '/v1/credentials/3456?metadata_only=false',
        follow_redirects=False
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert json_data['permissions']['update'] is True
    assert 'next_rotation_date' in json_data
    assert mock_save.call_count == 2  # Once for credential, once for archive

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

    # Archive credential not found
    # Fail open - still return a 200
    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=[credential, DoesNotExist()]
    )
    ret = app.test_client().get(
        '/v1/credentials/3456?metadata_only=false',
        follow_redirects=False
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200

    mocker.patch(
        'confidant.routes.credentials.Credential.get',
        side_effect=DoesNotExist(),
    )
    ret = app.test_client().get(
        '/v1/credentials/1234',
        follow_redirects=False,
    )
    assert ret.status_code == 404


def test_diff_credential(mocker: MockerFixture, credential: Credential):
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


def test_create_credential(mocker: MockerFixture, credential: Credential):
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
            'tags': ['ADMIN_PRIV', 'MY_SPECIAL_TAG'],
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert ['ADMIN_PRIV', 'MY_SPECIAL_TAG'] == json_data['tags']
    assert 'shiny new key' == json_data['name']
    assert mock_save.call_count == 2


def test_update_credential(mocker: MockerFixture, credential: Credential):
    credential.last_rotation_date = datetime(2020, 1, 1, tzinfo=pytz.UTC)
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

    # Empty credential pairs
    mocker.patch(
        ('confidant.routes.credentials.servicemanager'
         '.pair_key_conflicts_for_services'),
        return_value={},
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
        headers={"Content-Type": 'application/json'},
        data=json.dumps({
            'credential_pairs': {},
            'enabled': True,
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 400
    assert 'Credential Pairs cannot be empty.' == json_data['error']


    # Credential name already exists (ie: query returns a value)
    mocker.patch(
        'confidant.routes.credentials.Credential.data_type_date_index.query',
        return_value=[credential],
    )
    ret = app.test_client().put(
        '/v1/credentials/123',
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
            'tags': ['NEW SPECIAL TAG', 'DB_AUTH'],
        }),
    )
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert ['NEW SPECIAL TAG', 'DB_AUTH'] == json_data['tags']
    assert 'shiny new name' == json_data['name']
    assert mock_save.call_count == 2
    assert 'last_rotation_date' in json_data
    assert 'next_rotation_date' in json_data


def test_revise_credential(
    mocker: MockerFixture,
    credential: Credential,
    archive_credential: Credential
):
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
    assert ['OLD TAG'] == json_data['tags']
    assert 'Archive credential' == json_data['name']
    assert mock_save.call_count == 2
