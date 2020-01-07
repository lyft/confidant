from pynamodb.exceptions import DoesNotExist

from confidant import settings
from confidant.services import credentialmanager
from confidant.services import graphite
from confidant.models.service import Service


def get_services_for_credential(_id):
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.credentials:
            services.append(service)
    return services


def get_services_for_blind_credential(_id):
    services = []
    for service in Service.data_type_date_index.query('service'):
        if _id in service.blind_credentials:
            services.append(service)
    return services


def get_service_map(services):
    service_map = {}
    for service in services:
        for credential in service.credentials:
            if credential in service_map:
                service_map[credential]['service_ids'].append(service.id)
            else:
                service_map[credential] = {
                    'data_type': 'credential',
                    'service_ids': [service.id]
                }
        for credential in service.blind_credentials:
            if credential in service_map:
                service_map[credential]['service_ids'].append(service.id)
            else:
                service_map[credential] = {
                    'data_type': 'blind-credential',
                    'service_ids': [service.id]
                }
    return service_map


def pair_key_conflicts_for_services(_id, credential_keys, services):
    conflicts = {}
    # If we don't care about conflicts, return immediately
    if settings.IGNORE_CONFLICTS:
        return conflicts
    service_map = get_service_map(services)
    credential_ids = []
    blind_credential_ids = []
    for credential, data in service_map.items():
        if _id == credential:
            continue
        if data['data_type'] == 'credential':
            credential_ids.append(credential)
        elif data['data_type'] == 'blind-credential':
            blind_credential_ids.append(credential)
    credentials = credentialmanager.get_credentials(credential_ids)
    credentials.extend(
        credentialmanager.get_blind_credentials(blind_credential_ids)
    )
    for credential in credentials:
        services = service_map[credential.id]['service_ids']
        if credential.data_type == 'credential':
            data_type = 'credentials'
        elif credential.data_type == 'blind-credential':
            data_type = 'blind_credentials'
        for key in credential_keys:
            if key in credential.credential_keys:
                if key not in conflicts:
                    conflicts[key] = {
                        data_type: [credential.id],
                        'services': services
                    }
                else:
                    conflicts[key]['services'].extend(services)
                    conflicts[key][data_type].append(credential.id)
                conflicts[key]['services'] = list(
                    set(conflicts[key]['services'])
                )
                conflicts[key][data_type] = list(
                    set(conflicts[key][data_type])
                )
    return conflicts


def send_service_mapping_graphite_event(new_service, old_service):
    if old_service:
        old_credential_ids = old_service.credentials
    else:
        old_credential_ids = []
    added = list(set(new_service.credentials) - set(old_credential_ids))
    removed = list(set(old_credential_ids) - set(new_service.credentials))
    msg = 'Added credentials: {0}; Removed credentials {1}; Revision {2}'
    msg = msg.format(added, removed, new_service.revision)
    graphite.send_event([id], msg)


def get_latest_service_revision(id, revision):
    i = revision + 1
    while True:
        _id = '{0}-{1}'.format(id, i)
        try:
            Service.get(_id)
        except DoesNotExist:
            return i
        i = i + 1
