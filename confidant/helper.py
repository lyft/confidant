import json
from confidant import keymanager
from confidant.ciphermanager import CipherManager
from confidant.models.service import Service


def get_credential_context_id(cred):
    """
    Gets a context id for a credential (for encryption context during
    encryption/decryption).

    Arguments:
        cred: A Credential model.

    Returns: The context id as a string.
    """
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
    """
    Gets all services that use a credential.

    Arguments:
        _id: A Credential id.

    Returns: A list of Services.
    """
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.credentials:
            services.append(service)
    return services


def get_credential_pairs(cred):
    """
    Decrypts and returns all credential pairs for a credential.

    Arguments:
        cred: A Credential model.

    Returns: A dictionary of credential pairs.
    """
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
