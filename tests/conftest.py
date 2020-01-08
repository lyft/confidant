import pytest

from confidant import settings


@pytest.fixture(autouse=True)
def encrypted_settings_mock():
    settings.encrypted_settings.secret_string = {}
    settings.encrypted_settings.decrypted_secrets = {
        'SESSION_SECRET': 'TEST_KEY'
    }
