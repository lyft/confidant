import sys
import os
import base64
import json
import yaml

from cryptography.fernet import Fernet
from flask_script import Command, Option

import confidant.clients
from confidant import settings
from confidant.lib import cryptolib


class GenerateSecretsBootstrap(Command):

    option_list = [
        Option(
            '--in',
            dest='_in',
            default='-',
            help='Path to YAML file containing all the secrets',
        ),
        Option('--out', dest='_out', default='-')
    ]

    def run(self, _in, _out):
        if _in == '-':
            secrets = sys.stdin.read()
        else:
            with open(os.path.join(_in), 'r') as f:
                secrets = f.read()
        client = confidant.clients.get_boto_client(
            'kms',
            endpoint_url=settings.KMS_URL,
        )
        data_key = cryptolib.create_datakey(
            {'type': 'bootstrap'},
            settings.KMS_MASTER_KEY,
            client=client,
        )
        f = Fernet(data_key['plaintext'])
        data = {
            'data_key': base64.b64encode(
                data_key['ciphertext'],
            ).decode('utf-8'),
            'secrets': f.encrypt(secrets.encode('utf-8')).decode('utf-8'),
        }
        data = json.dumps(data)
        if _out == '-':
            print(data)
        else:
            with open(os.path.join(_out), 'w') as f:
                f.write(data)


class DecryptSecretsBootstrap(Command):

    option_list = [
        Option('--out', dest='_out', default='-')
    ]

    def run(self, _out):
        data = settings.encrypted_settings.get_all_secrets()
        data = yaml.safe_dump(data, default_flow_style=False, indent=2)
        if _out == '-':
            print(data)
        else:
            with open(os.path.join(_out), 'w') as f:
                f.write(data)
