import sys
import os
import logging
import base64
import json
import yaml

from cryptography.fernet import Fernet
from flask_script import Command, Option

from confidant import settings
from confidant.lib import cryptolib

logger = logging.getLogger(__name__)
logger.addHandler(logging.StreamHandler(sys.stdout))
logger.setLevel(logging.INFO)


class GenerateSecretsBootstrap(Command):

    option_list = [
        Option('--in', dest='_in', default='-'),
        Option('--out', dest='_out', default='-')
    ]

    def run(self, _in, _out):
        if _in == '-':
            secrets = sys.stdin.read()
        else:
            with open(os.path.join(_in), 'r') as f:
                secrets = f.read()
        data_key = cryptolib.create_datakey(
            {'type': 'bootstrap'},
            settings.KMS_MASTER_KEY,
        )
        f = Fernet(data_key['plaintext'])
        data = {
            'data_key': base64.b64encode(data_key['ciphertext']),
            'secrets': f.encrypt(secrets.encode('utf-8'))
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
