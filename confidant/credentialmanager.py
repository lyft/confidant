from confidant import keymanager
from confidant.ciphermanager import CipherManager
from confidant.models.credential import Credential


def encrypt_credential(credential_pairs, encryption_context):
    cipher_version = 2
    regions = keymanager.get_datakey_regions()
    data_key = {}
    credential_pairs = {}
    for region in regions:
        _data_key = keymanager.create_datakey(encryption_context={'id': id})
        data_key[region] = _data_key['ciphertext']
        cipher = CipherManager(_data_key['plaintext'], version=cipher_version)
        credential_pairs[region] = cipher.encrypt(credential_pairs)
    return {
        'data_key': data_key,
        'credential_pairs': credential_pairs,
        'cipher_version': cipher_version
    }


def save_credential(
        id,
        revision,
        name,
        encrypted_data,
        metadata,
        enabled,
        modified_by
        ):
    cred = Credential(
        id='{0}-{1}'.format(id, revision),
        data_type='archive-credential',
        name=name,
        credential_pairs=encrypted_data['credential_pairs'],
        metadata=metadata,
        revision=revision,
        enabled=enabled,
        data_key=encrypted_data['data_key'],
        cipher_version=encrypted_data['cipher_version'],
        schema_version=encrypted_data['schema_version'],
        modified_by=modified_by
    ).save(id__null=True)
    # Make this the current revision
    cred = Credential(
        id=id,
        data_type='credential',
        name=name,
        credential_pairs=encrypted_data['credential_pairs'],
        metadata=metadata,
        revision=revision,
        enabled=enabled,
        data_key=encrypted_data['data_key'],
        cipher_version=encrypted_data['cipher_version'],
        schema_version=encrypted_data['schema_version'],
        modified_by=modified_by
    )
    cred.save()
    return cred
