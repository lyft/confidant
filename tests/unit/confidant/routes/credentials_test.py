from datetime import datetime

import pytest

from confidant.app import create_app
from confidant.models.credential import Credential


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
    mocker.patch('confidant.settings.USE_AUTH', False)
    mocker.patch(
        'confidant.routes.credentials.authnz.get_logged_in_user',
        return_value='test@example.com',
    )
    mocker.patch(
        'confidant.routes.credentials.acl_module_check',
        return_value=False,
    )
    mocker.patch(
        'confidant.models.credential.Credential.data_type_date_index.query',
        return_value=credential_list,
    )

    app = create_app()
    ret = app.test_client().get('/v1/credentials', follow_redirects=False)
    assert ret.status_code == 403
