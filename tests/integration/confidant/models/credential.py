import json
import uuid

from confidant import keymanager
from confidant.app import app  # noqa: need to initialize app, but unused
from confidant.ciphermanager import CipherManager
from confidant.models.legacy.v1.credential import Credential as v1Credential
from confidant.models.legacy.v1.blind_credential import (
    BlindCredential as v1BlindCredential
)
from confidant.models.credential import Credential
from confidant.models.service import Service


def test_v1_to_v2_schama_migration():
    # First save a v1 credential
    v1_cred_id = str(uuid.uuid4()).replace('-', '')
    credential_pairs = {
        'key1': 'val1',
        'key2': 'val2',
    }
    revision = 1
    _credential_pairs = json.dumps(credential_pairs)
    data_key = keymanager.create_datakey(
        encryption_context={'id': id},
        region='us-east-1'
    )
    cipher = CipherManager(data_key['plaintext'], version=2)
    _credential_pairs = cipher.encrypt(credential_pairs)
    v1_cred = v1Credential(
        id='{0}-{1}'.format(v1_cred_id, revision),
        data_type='archive-credential',
        name='cred1',
        credential_pairs=_credential_pairs,
        metadata={},
        revision=revision,
        enabled=True,
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by='rlane@lyft.com',
        documentation='test docs',
    ).save(id__null=True)
    # Make this the current revision
    v1_cred = v1Credential(
        id=v1_cred_id,
        data_type='credential',
        name='cred1',
        credential_pairs=_credential_pairs,
        metadata={},
        revision=revision,
        enabled=True,
        data_key=data_key['ciphertext'],
        cipher_version=2,
        modified_by='rlane@lyft.com',
        documentation='test docs',
    )
    v1_cred.save()

    # Next save a v1 blind credential
    v1_blind_cred_id = str(uuid.uuid4()).replace('-', '')
    v1_blind_cred = v1BlindCredential(
        id='{0}-{1}'.format(v1_blind_cred_id, revision),
        data_type='archive-blind-credential',
        name='blind_cred1',
        credential_pairs={'us-east-1': 'abcd1234', 'us-west-1': 'qwery0987'},
        credential_keys=['key1', 'key2'],
        metadata={'us-east-1': {'group': 'confidant-test'}},
        revision=revision,
        enabled=True,
        data_key={'us-east-1': 'zzzz1234', 'us-west-1': 'qqqq0987'},
        cipher_type='fernet',
        cipher_version=2,
        modified_by='rlane@lyft.com',
        documentation='test docs',
    ).save(id__null=True)
    v1_blind_cred = v1BlindCredential(
        id=id,
        data_type='blind-credential',
        name='blind_cred1',
        credential_pairs={'us-east-1': 'abcd1234', 'us-west-1': 'qwery0987'},
        credential_keys=['key1', 'key2'],
        metadata={'us-east-1': {'group': 'confidant-test'}},
        revision=revision,
        enabled=True,
        data_key={'us-east-1': 'zzzz1234', 'us-west-1': 'qqqq0987'},
        cipher_type='fernet',
        cipher_version=2,
        modified_by='rlane@lyft.com',
        documentation='test docs',
    )
    v1_blind_cred.save()

    # Next make sure we can load a v1 credential in a v2 model
    cred = Credential.get(v1_cred_id)
    assert cred.blind is False
    assert credential_pairs == cred.decrypted_credential_pairs

    # Next make sure we can load a v1 blind credential in a v2 model
    cred = Credential.get(v1_blind_cred_id)
    assert cred.blind is True
    assert cred.decrypted_credential_pairs is None

    # Next make a service with both added
    service_id = str(uuid.uuid4()).replace('-', '')
    Service(
        id='{0}-{1}'.format(service_id, revision),
        data_type='archive-service',
        credentials=[v1_cred_id],
        blind_credentials=[v1_blind_cred_id],
        account=None,
        enabled=True,
        revision=revision,
        modified_by='rlane@lyft.com',
    ).save(id__null=True)

    service = Service(
        id=service_id,
        data_type='service',
        credentials=[v1_cred_id],
        blind_credentials=[v1_blind_cred_id],
        account=None,
        enabled=True,
        revision=revision,
        modified_by='rlane@lyft.com',
    )
    service.save()
