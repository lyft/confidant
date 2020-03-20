import pytest
from confidant.services import keymanager


@pytest.fixture
def mock_auth_client(mocker):
    return mocker.patch(
        'confidant.services.keymanager._get_auth_kms_client',
    )


def test_get_key_id(mocker, mock_auth_client):
    mocker.patch('confidant.services.keymanager._KEY_METADATA', {})
    mock_auth_client.describe_key = mocker.Mock(
        return_value={'KeyMetadata': {'KeyId': 'mockid'}}
    )
    assert keymanager.get_key_id('mockalias') == 'mockid'


def test_get_key_id_cached(mocker, mock_auth_client):
    mocker.patch(
        'confidant.services.keymanager._KEY_METADATA',
        {'mockalias': {'KeyMetadata': {'KeyId': 'mockid'}}}
    )
    mock_auth_client.describe_key = mocker.Mock()
    assert keymanager.get_key_id('mockalias') == 'mockid'


def test_create_datakey_mocked(mocker):
    fernet_mock = mocker.patch('cryptography.fernet.Fernet.generate_key')
    fernet_mock.return_value = 'mocked_fernet_key'
    mocker.patch('confidant.services.keymanager.settings.USE_ENCRYPTION', False)

    ret = keymanager.create_datakey({})

    assert fernet_mock.called is True

    # Assert that we got a dict returned where the ciphertext and plaintext
    # keys are equal
    assert ret['ciphertext'] == ret['plaintext']

    # Assert ciphertext is mocked_fernet_key
    assert ret['ciphertext'] == 'mocked_fernet_key'


def test_decrypt_datakey_mocked(mocker):
    mocker.patch('confidant.services.keymanager.settings.USE_ENCRYPTION', False)
    ret = keymanager.decrypt_datakey('mocked_fernet_key')

    # Ensure we get the same value out that we sent in.
    assert ret == 'mocked_fernet_key'


def test_create_datakey_with_encryption(mocker):
    cd_mock = mocker.patch(
        'confidant.services.keymanager.cryptolib.create_datakey'
    )
    cmd_mock = mocker.patch(
        'confidant.services.keymanager.cryptolib.create_mock_datakey'
    )
    mocker.patch('confidant.services.keymanager.settings.USE_ENCRYPTION', True)
    context = {'from': 'confidant-development',
               'to': 'confidant-development'}
    keymanager.create_datakey(context)

    # Assert that create_datakey was called and create_mock_datakey was
    # not called.
    assert cd_mock.called is True
    assert cmd_mock.called is False


def test_decrypt_datakey_with_encryption(mocker):
    dd_mock = mocker.patch(
        'confidant.services.keymanager.cryptolib.decrypt_datakey'
    )
    dmd_mock = mocker.patch(
        'confidant.services.keymanager.cryptolib.decrypt_mock_datakey'
    )

    mocker.patch('confidant.services.keymanager.settings.USE_ENCRYPTION', True)
    context = {'from': 'confidant-development',
               'to': 'confidant-development'}
    keymanager.decrypt_datakey(b'encrypted', context)

    # Assert that decrypt_datakey was called and decrypt_mock_datakey was
    # not called.
    assert dd_mock.called is True
    assert dmd_mock.called is False
