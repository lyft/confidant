import json

from confidant import keymanager
from confidant.ciphermanager import CipherManager
from confidant.models.credential import Credential


def _encrypt_credential(credential_pairs, encryption_context, cipher_version=2):
    regions = keymanager.get_datakey_regions()
    data_key = {}
    _credential_pairs = {}
    for region in regions:
        _data_key = keymanager.create_datakey(
            encryption_context=encryption_context,
            region=region
        )
        data_key[region] = _data_key['ciphertext']
        cipher = CipherManager(_data_key['plaintext'], version=cipher_version)
        _credential_pairs[region] = cipher.encrypt(credential_pairs)
    return {
        'data_key': json.dumps(data_key),
        'credential_pairs': json.dumps(_credential_pairs),
        'cipher_version': cipher_version
    }


def save_credential(
        id,
        revision,
        name,
        blind,
        credential_pairs,
        encryption_context,
        metadata,
        enabled,
        modified_by,
        credential_keys=None,
        cipher_version=2,
        cipher_type='fernet',
        data_key=None
        ):
    if blind:
        # blind credentials are pre-encrypted
        _credential_pairs = credential_pairs
        if credential_keys is None:
            _credential_keys = []
        else:
            _credential_keys = credential_keys
    else:
        encrypted_data = _encrypt_credential(
            credential_pairs,
            encryption_context,
            cipher_version=cipher_version
        )
        _credential_pairs = encrypted_data['credential_pairs']
        # TODO: add a setting for this and include the keys, if the setting is
        # true.
        _credential_keys = []
        data_key = encrypted_data['data_key']
    cred = Credential(
        id='{0}-{1}'.format(id, revision),
        data_type='archive-credential',
        name=name,
        blind=blind,
        credential_pairs=_credential_pairs,
        credential_keys=json.dumps(_credential_keys),
        metadata=json.dumps(metadata),
        revision=revision,
        enabled=enabled,
        data_key=data_key,
        cipher_version=cipher_version,
        cipher_type=cipher_type,
        schema_version=2,
        modified_by=modified_by
    ).save(id__null=True)
    # Make this the current revision
    cred = Credential(
        id=id,
        data_type='credential',
        name=name,
        blind=blind,
        credential_pairs=_credential_pairs,
        credential_keys=json.dumps(_credential_keys),
        metadata=json.dumps(metadata),
        revision=revision,
        enabled=enabled,
        data_key=data_key,
        cipher_version=cipher_version,
        cipher_type=cipher_type,
        schema_version=2,
        modified_by=modified_by
    )
    cred.save()
    return cred
