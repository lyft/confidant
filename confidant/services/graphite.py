import requests
import json
import logging

from confidant import settings

logger = logging.getLogger(__name__)


def send_event(services, msg):
    try:
        graphite_url = settings.GRAPHITE_EVENT_URL
        if not graphite_url:
            return
        username = settings.GRAPHITE_USERNAME
        password = settings.GRAPHITE_PASSWORD
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
            timeout=3
        )
        if response.status_code != 200:
            msg = 'Post to graphite returned non-2000 status ({0}).'
            logger.warning(msg.format(response.status_code))
    except Exception as e:
        logger.warning('Failed to post graphite event. {0}'.format(e))
