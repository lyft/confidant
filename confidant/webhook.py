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

    # New logic to support reading Webhook configuration from a file
    webhook_file = app.config.get('WEBHOOK_ARRAY_FILE')
    if not webhook_file:
        logging.debug('Failed to find WEBHOOK_ARRAY_FILE in config')
        return
    try:
        with open(webhook_file) as json_file:
            webhook_array = json.load(json_file)
            for endpoint in webhook_array:
                try:
                    logging.debug('Endpoint: ' + endpoint['WEBHOOK_URL'])
                    webhook_url = endpoint['WEBHOOK_URL']
                    headers = {'Content-type': 'application/json', 'Accept': 'text/plain'}

                    event = {
                        'event_type': event_type,
                        'services': services,
                        'credentials': credential_ids
                    }
                    response = []
                    if 'WEBHOOK_USERNAME' in endpoint:
                        logging.debug('Username: ' + endpoint['WEBHOOK_USERNAME'])
                        username = endpoint['WEBHOOK_USERNAME']
                        password = endpoint['WEBHOOK_PASSWORD'] # Assumed if above
                        response = requests.post(
                            webhook_url,
                            auth=(username, password),
                            headers=headers,
                            data=json.dumps(event),
                            timeout=3
                        )
                    else:
                        response = requests.post(
                            webhook_url,
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
    except ValueError as e:
        logging.warning('Failed to decode JSON file: {0}'.format(webhook_file))
    except EnvironmentError:
        logging.warning('Failed to open file: {0}'.format(webhook_file))
