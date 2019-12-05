from confidant.app import app
from confidant.services import credentialmanager
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
    if app.config['IGNORE_CONFLICTS']:
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
        services = service_map[credential['id']]['service_ids']
        if credential['data_type'] == 'credential':
            data_type = 'credentials'
            lookup = 'credential_pairs'
        elif credential['data_type'] == 'blind-credential':
            data_type = 'blind_credentials'
            lookup = 'credential_keys'
        for key in credential_keys:
            if key in credential[lookup]:
                if key not in conflicts:
                    conflicts[key] = {
                        data_type: [credential['id']],
                        'services': services
                    }
                else:
                    conflicts[key]['services'].extend(services)
                    conflicts[key][data_type].append(credential['id'])
                conflicts[key]['services'] = list(
                    set(conflicts[key]['services'])
                )
                conflicts[key][data_type] = list(
                    set(conflicts[key][data_type])
                )
    return conflicts
