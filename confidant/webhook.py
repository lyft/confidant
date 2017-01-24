import requests
import json
import logging

from confidant.app import app


def send_event(event_type, services, credential_ids):
    try:
        webhook_url = app.config.get('WEBHOOK_URL')
        if not webhook_url:
            logging.debug('Failed to find a WEBHOOK_URL in config')
            return
        username = app.config.get('WEBHOOK_USERNAME')
        password = app.config.get('WEBHOOK_PASSWORD')
        headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

        event = {
            'event_type': event_type,
            'services': services,
            'credentials': credential_ids
        }
        response = requests.post(
            webhook_url,
            auth=(username, password),
            headers=headers,
            data=json.dumps(event),
            timeout=3
        )
        if response.status_code != 200:
            msg = 'Post to webhook returned non-200 status ({0}).'
            logging.warning(msg.format(response.status_code))
        logging.warning("webhook triggered: {}".format(event))
    except Exception as e:
        logging.warning('Failed to post webhook event. {0}'.format(e))
