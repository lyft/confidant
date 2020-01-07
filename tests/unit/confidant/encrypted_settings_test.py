from confidant.encrypted_settings import EncryptedSettings


def test_register():
    enc_set = EncryptedSettings(None)
    enc_set.register('Foo', 'Bar')
    assert enc_set.secret_names == ['Foo']


def test_get_registered():
    enc_set = EncryptedSettings(None)
    enc_set.register('Foo', 'Bar')
    enc_set.decrypted_secrets = {'Foo': 'DecryptedBar'}
    assert enc_set.get_secret('Foo') == 'DecryptedBar'


def test_get_registered_default():
    enc_set = EncryptedSettings(None)
    enc_set.register('Foo', 'Bar')
    enc_set.register('Bar', 'Baz')
    enc_set.decrypted_secrets = {'Foo': 'DecryptedFoo'}
    assert enc_set.get_secret('Bar') == 'Baz'


def test_bootstrap(mocker):
    mocker.patch(
        'confidant.encrypted_settings.cryptolib.decrypt_datakey',
        return_value='1cVUbJT58SbMt4Wk4xmEZoNhZGdWO_vg1IJiXwc6HGs'
    )
    mocker.patch(
        'confidant.encrypted_settings.Fernet.decrypt',
        return_value='{secret: value, secret2: value2}\n'
    )
    enc_set = EncryptedSettings(None)
    decrypted = enc_set._bootstrap(
        '{"secrets": "encryptedstring", "data_key": "dGhla2V5"}'
    )
    assert decrypted['secret2'] == 'value2'


def test_bootstrap_filefail():
    enc_set = EncryptedSettings(None)
    decrypted = enc_set._bootstrap('file://FILE/DOES/NOT/EXIST')
    assert decrypted == {}
