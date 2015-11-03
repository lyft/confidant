'''
Set service_*, and region grains based on environment variables.
'''
import os


def parse_env():
    service_name = os.environ.get('SERVICE_NAME')
    service_instance = os.environ.get('SERVICE_INSTANCE')
    region = os.environ.get('REGION')
    service_group = '{0}-{1}'.format(service_name, service_instance, region)
    cluster_name = '{0}-{1}'.format(service_group, region)
    return {
        'service_name': service_name,
        'service_instance': service_instance,
        'region': region,
        'service_group': service_group,
        'cluster_name': cluster_name
    }
