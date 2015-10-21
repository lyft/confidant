# -*- coding: utf-8 -*-
# Import python libs
import logging
import datetime
import base64
import json
import argparse
import sys

# Import third party libs
import requests
import boto3

# shut up requests module
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# shut up boto3 and botocore
boto3.set_stream_logger(level=logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)


def get_service(url, from_context, to_context, auth_key, token_lifetime=1):
    '''
    Read secret data from Confidant via its API.
    '''
    # Return a dict, always with an attribute that specifies whether or not the
    # function was able to successfully get a result.
    ret = {'result': False}
    # Populate the auth encryption context dict that'll be used for KMS.
    auth_context = {
        'from': from_context,
        'to': to_context
    }
    # Specify the standard time format for dates required by Confidant.
    time_format = "%Y%m%dT%H%M%SZ"
    # Generate string formatted timestamps for not_before and not_after, for
    # the lifetime specified in minutes.
    now = datetime.datetime.utcnow()
    not_before = now.strftime(time_format)
    _not_after = now + datetime.timedelta(minutes=token_lifetime)
    not_after = _not_after.strftime(time_format)
    # Generate a json string for the encryption payload contents.
    payload = json.dumps({
        'not_before': not_before,
        'not_after': not_after
    })
    try:
        kms = boto3.client('kms')
    except Exception:
        logging.exception('Failed to connect to KMS.')
        return ret
    try:
        # Generate a base64 encoded KMS encrypted token to use for
        # authentication. We encrypt the token lifetime information as the
        # payload for verification in Confidant.
        token = kms.encrypt(
            KeyId=auth_key,
            Plaintext=payload,
            EncryptionContext=auth_context
        )['CiphertextBlob']
        token = base64.b64encode(token)
    except Exception:
        logging.exception('Failed to create auth token.')
        return ret
    try:
        # Make a request to confidant with the provided url, to fetch the
        # service (from_context), providing the from context and base64 encoded
        # token for authentication.
        response = requests.get(
            '{0}/v1/services/{1}'.format(url, from_context),
            auth=(from_context, token),
            allow_redirects=False,
            timeout=2
        )
    except requests.ConnectionError:
        logging.error('Failed to connect to confidant.')
        return ret
    except requests.Timeout:
        logging.error('Confidant request timed out.')
        return ret
    if response.status_code == 404:
        logging.debug('Service not found in confidant.')
        return ret
    elif response.status_code == 401:
        logging.error('Authentication or authorization failed.')
        return ret
    elif response.status_code != 200:
        msg = 'Received unexpected return from confidant (status: {0})'
        msg = msg.format(response.status_code)
        logging.error(msg)
        return ret
    try:
        data = response.json()
    except ValueError:
        logging.error('Received badly formatted json data from confidant.')
        return ret
    ret['service'] = data
    ret['result'] = True
    return ret


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description='A client for fetching secrets from a confidant server.',
        epilog=('example: python confidant_client.py -u'
                ' "https://confidant-production.example.com" -k'
                ' "alias/authnz-production" myservice-production'
                ' confidant-production')
    )
    parser.add_argument(
        '-u',
        '--url',
        required=True,
        help=('url of the confidant server. i.e.'
              ' https://confidant-production.example.com')
    )
    parser.add_argument(
        '-k',
        '--auth-key',
        required=True,
        help='The KMS auth key to use. i.e. alias/authnz-production'
    )
    parser.add_argument(
        '-l',
        '--token-lifetime',
        type=int,
        help='The token lifetime, in minutes.',
        default=1
    )
    parser.add_argument(
        'from_context',
        help='The IAM role requesting the secrets. i.e. myservice-production'
    )
    parser.add_argument(
        'to_context',
        help='The IAM role name of confidant. i.e. confidant-production'
    )
    parser.add_argument(
        '--log-level',
        help='Logging verbosity.',
        default='info'
    )
    args = parser.parse_args()
    numeric_loglevel = getattr(logging, args.log_level.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: {0}'.format(args.loglevel))
    logging.basicConfig(
        level=numeric_loglevel,
        format='%(asctime)s %(name)s: %(levelname)s %(message)s',
        stream=sys.stderr
    )
    ret = get_service(
        args.url,
        args.from_context,
        args.to_context,
        args.auth_key,
        args.token_lifetime
    )
    sys.stdout.write('{0}\n'.format(json.dumps(ret)))
