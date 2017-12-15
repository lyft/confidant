import json
from confidant import keymanager
from confidant.ciphermanager import CipherManager
from confidant.models.service import Service


def get_credential_context_id(cred):
    if cred.data_type == 'credential':
        context = cred.id
    elif cred.data_type == 'archive-credential':
        context = cred.id.split('-')[0]
    else:
        # Cannot decrypt blind credential or anything other data type
        raise ValueError(
            'Expected credential or archive-credential data type'
        )
    return context


def get_services_for_credential(_id):
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.credentials:
            services.append(service)
    return services


def get_credential_pairs(cred):
    context = get_credential_context_id(cred)
    data_key = keymanager.decrypt_datakey(
        cred.data_key,
        encryption_context={'id': context}
    )
    cipher_version = cred.cipher_version
    cipher = CipherManager(data_key, cipher_version)
    credential_pairs = cipher.decrypt(cred.credential_pairs)
    credential_pairs = json.loads(credential_pairs)
    return credential_pairs
