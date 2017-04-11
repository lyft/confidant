import yaml
import base64
import logging
import json

from cryptography.fernet import Fernet
from confidant.lib import cryptolib


class EncryptedSettings(object):

    def __init__(self, secret_string):
        self.secret_names = []
        self.secret_defaults = {}
        self.secret_string = secret_string
        self.decrypted_secrets = None

    def register(self, name, default):
        """
        Lazy setup things that we want to get if we have kms
        """
        if name not in self.secret_names:
            self.secret_names.append(name)
            self.secret_defaults[name] = default

    def registered(self, name):
        return name in self.secret_names

    def get_secret(self, name):
        if self.decrypted_secrets is None:
            self.decrypted_secrets = self._bootstrap(self.secret_string)
        return self.decrypted_secrets.get(name, self.secret_defaults[name])

    def get_all_secrets(self):
        secrets = {}
        for name in self.secret_names:
            secrets[name] = self.get_secret(name)
        return secrets

    def _bootstrap(self, secrets):
        """
        Decrypt secrets and return a dict of secrets. Uses KMS to decrypt.
        """
        if not secrets:
            logging.info('SECRETS_BOOTSTRAP not set, skipping bootstrapping.')
            return {}
        if secrets.startswith('file://'):
            try:
                with open(secrets[7:], 'r') as f:
                    _secrets = json.load(f)
            except IOError:
                logging.error(
                    'Failed to load file specified in SECRETS_BOOTSTRAP.'
                )
                return {}
        else:
            _secrets = json.loads(secrets)
        key = cryptolib.decrypt_datakey(
            base64.b64decode(_secrets['data_key']),
            {'type': 'bootstrap'}
        )
        f = Fernet(key)
        decrypted_secrets = yaml.safe_load(
            f.decrypt(_secrets['secrets'].encode('utf-8'))
        )
        logging.info('Loaded SECRETS_BOOTSTRAP.')
        return decrypted_secrets
