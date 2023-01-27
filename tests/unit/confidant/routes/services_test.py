import json
import pytest

from unittest import mock

from confidant.app import create_app
from confidant.models.service import Service


@pytest.fixture()
def services_list(mocker):
    services = [
        Service(
            id='something-production-iad',
            data_type='service',
            credentials=set(),
            blind_credentials=set(),
            enabled=True,
            revision=1,
            modified_by='user'
        ),
        Service(
            id='another-production-iad',
            data_type='service',
            credentials=set(),
            blind_credentials=set(),
            enabled=True,
            revision=1,
            modified_by='user'
        ),
    ]
    return services


def test_get_services_list(mocker, services_list):
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
    ret = app.test_client().get('/v1/services', follow_redirects=False)
    assert ret.status_code == 403

    mocker.patch(
        'confidant.routes.services.acl_module_check',
        return_value=True,
    )
    mocker.patch(
        'confidant.models.service.Service.data_type_date_index.query',
        return_value=services_list,
    )
    ret = app.test_client().get('/v1/services', follow_redirects=False)
    service_ids = ['another-production-iad', 'something-production-iad']
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['services']) == len(services_list)
    assert json_data['next_page'] is None
    assert json_data['services'][0]['id'] in service_ids
    assert json_data['services'][1]['id'] in service_ids

    mock_service_list = mock.Mock()
    mock_service_list.last_evaluated_key.return_value = {
        'something': 'test'
    }
    mock_service_list.__iter__ = mock.Mock(
        return_value=iter([services_list[0]])
    )
    mocker.patch(
        'confidant.models.service.Service.data_type_date_index.query',
        return_value=mock_service_list,
    )
    mocker.patch(
        'confidant.schema.services.encode_last_evaluated_key',
        return_value='{"something":"test"}',
    )
    ret = app.test_client().get('/v1/services?limit=1', follow_redirects=False)
    json_data = json.loads(ret.data)
    assert ret.status_code == 200
    assert len(json_data['services']) == 1
