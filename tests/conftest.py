import pytest


@pytest.fixture(autouse=True)
def encrypted_settings_mock(mocker):
    mocker.patch('confidant.settings.encrypted_settings.secret_string', {})
    mocker.patch(
        'confidant.settings.encrypted_settings.decrypted_secrets',
        {'SESSION_SECRET': 'TEST_KEY'},
    )
