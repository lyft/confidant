from . import app
from . import log

import requests
import json


def send_event(services, msg):
    try:
        graphite_url = app.config.get('GRAPHITE_EVENT_URL')
        if not graphite_url:
            return
        username = app.config.get('GRAPHITE_USERNAME')
        password = app.config.get('GRAPHITE_PASSWORD')
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}
        prefixed_services = ['confidant-{0}'.format(service)
                             for service in services]
        event = {
            'what': 'confidant',
            'tags': ','.join(['confidant'] + prefixed_services),
            'data': msg
        }
        response = requests.post(
            graphite_url,
            auth=(username, password),
            headers=headers,
            data=json.dumps(event),
            timeout=1
        )
        if response.status_code != 200:
            msg = 'Post to graphite returned non-2000 status ({0}).'
            log.warning(msg.format(response.status_code))
    except Exception as e:
        log.warning('Failed to post graphite event. {0}'.format(e))
