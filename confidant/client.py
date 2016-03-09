"""A client module for Confidant."""

import logging
import json
import datetime
import base64
import os

# Import third party libs
import requests
import boto3
from cryptography.fernet import Fernet
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util import Retry

import confidant.workarounds  # noqa
import confidant.services
from confidant.lib import cryptolib

# shut up requests module
logging.getLogger('requests').setLevel(logging.WARNING)
logging.getLogger('urllib3').setLevel(logging.WARNING)

# shut up boto3 and botocore
boto3.set_stream_logger(level=logging.WARNING)
logging.getLogger('botocore').setLevel(logging.WARNING)

JSON_HEADERS = {'Content-type': 'application/json', 'Accept': 'text/plain'}
TOKEN_SKEW = 3
TIME_FORMAT = "%Y%m%dT%H%M%SZ"


class ConfidantClient(object):

    """A class that represents a confidant client."""

    def __init__(
            self,
            url,
            auth_key,
            auth_context,
            token_lifetime=10,
            token_version=2,
            token_cache_file='/dev/shm/confidant/confidant_token',
            assume_role=None,
            mfa_pin=None,
            region=None,
            retries=0,
            backoff=1
            ):
        """Create a ConfidantClient object."""
        self.url = url
        self.auth_key = auth_key
        self.auth_context = auth_context
        self.token_lifetime = token_lifetime
        self.token_version = token_version
        self.token_cache_file = token_cache_file
        self.region = region
        self.retries = retries
        self.backoff = backoff
        # Use session to re-try failed requests.
        self.request_session = requests.Session()
        for proto in ['http://', 'https://']:
            self.request_session.mount(
                proto,
                HTTPAdapter(
                    max_retries=Retry(
                        total=self.retries,
                        status_forcelist=[500, 503],
                        backoff_factor=self.backoff
                    )
                )
            )
        self.validate_client()
        self.iam_client = confidant.services.get_boto_client(
            'iam',
            region=region
        )
        self.sts_client = confidant.services.get_boto_client(
            'sts',
            region=region
        )
        self.kms_client = confidant.services.get_boto_client(
            'kms',
            region=region
        )
        if assume_role:
            self.aws_creds = self._get_assume_role_creds(assume_role, mfa_pin)
        elif mfa_pin:
            self.aws_creds = self._get_mfa_creds(mfa_pin)
        else:
            self.aws_creds = None

    def validate_client(self):
        """Ensure the configuration passed into init is valid."""
        for key in ['from', 'to']:
            if key not in self.auth_context:
                raise ClientConfigurationError(
                    '{0} missing from auth_context.'.format(key)
                )
        if self.token_version > 1:
            if 'user_type' not in self.auth_context:
                raise ClientConfigurationError(
                    'user_type missing from auth_context.'
                )
        if self.token_version > 2:
            raise ClientConfigurationError(
                'Invalid token_version provided.'
            )

    def _get_username(self):
        """Get a username formatted for a specific token version."""
        _from = self.auth_context['from']
        if self.token_version == 1:
            return '{0}'.format(_from)
        elif self.token_version == 2:
            _user_type = self.auth_context['user_type']
            return '{0}/{1}/{2}'.format(
                self.token_version,
                _user_type,
                _from
            )

    def _get_assume_role_creds(self, role, mfa_pin=None):
        """Get AWS credentials for the specified role."""
        user = self.iam_client.get_user()
        base_arn = user['User']['Arn'].rsplit(':', 1)[0]
        role_arn = '{0}:role/{1}'.format(base_arn, role)
        username = user['User']['UserName']
        if mfa_pin:
            mfa_arn = '{0}:mfa/{1}'.format(base_arn, username)
            return self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='{0}_confidant'.format(username),
                SerialNumber=mfa_arn,
                TokenCode=mfa_pin
            )['Credentials']
        else:
            return self.sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName='{0}_confidant'.format(username)
            )['Credentials']

    def _get_mfa_creds(self, mfa_pin):
        """Get an AWS session token credentials, assumed with MFA."""
        user = self.iam_client.get_user()
        base_arn = user['User']['Arn'].rsplit(':', 1)[0]
        mfa_arn = '{0}:mfa/{1}'.format(base_arn, user['User']['UserName'])
        return self.sts_client.get_session_token(
            SerialNumber=mfa_arn,
            TokenCode=mfa_pin
        )['Credentials']

    def _get_cached_token(self):
        token = None
        if not self.token_cache_file:
            return token
        try:
            with open(self.token_cache_file, 'r') as f:
                token_data = json.load(f)
            _not_after = token_data['not_after']
            _auth_context = token_data['auth_context']
            _token = token_data['token']
            _not_after_cache = datetime.datetime.strptime(
                _not_after,
                TIME_FORMAT
            )
        except IOError as e:
            logging.info(
                'Failed to read confidant auth token cache: {0}'.format(e)
            )
            return token
        except Exception:
            logging.exception('Failed to read confidant auth token cache.')
            return token
        skew_delta = datetime.timedelta(minutes=TOKEN_SKEW)
        _not_after_cache = _not_after_cache - skew_delta
        now = datetime.datetime.utcnow()
        if now <= _not_after_cache and _auth_context == self.auth_context:
            logging.debug('Using confidant auth token cache.')
            token = _token
        return token

    def _cache_token(self, token, not_after):
        if not self.token_cache_file:
            return
        try:
            cachedir = os.path.dirname(self.token_cache_file)
            if not os.path.exists(cachedir):
                os.makedirs(cachedir)
            with open(self.token_cache_file, 'w') as f:
                json.dump({
                    'token': token,
                    'not_after': not_after,
                    'auth_context': self.auth_context
                }, f)
        except Exception:
            logging.exception('Failed to write confidant auth token cache.')

    def _get_token(self):
        """Get an authentication token."""
        # Generate string formatted timestamps for not_before and not_after,
        # for the lifetime specified in minutes.
        now = datetime.datetime.utcnow()
        # Start the not_before time x minutes in the past, to avoid clock skew
        # issues.
        _not_before = now - datetime.timedelta(minutes=TOKEN_SKEW)
        not_before = _not_before.strftime(TIME_FORMAT)
        # Set the not_after time in the future, by the lifetime, but ensure the
        # skew we applied to not_before is taken into account.
        _not_after = now + datetime.timedelta(
            minutes=self.token_lifetime - TOKEN_SKEW
        )
        not_after = _not_after.strftime(TIME_FORMAT)
        # Generate a json string for the encryption payload contents.
        payload = json.dumps({
            'not_before': not_before,
            'not_after': not_after
        })
        token = self._get_cached_token()
        if token:
            return token
        # Generate a base64 encoded KMS encrypted token to use for
        # authentication. We encrypt the token lifetime information as the
        # payload for verification in Confidant.
        if self.aws_creds:
            _kms_client = confidant.services.get_boto_client(
                'kms',
                region=self.region,
                aws_access_key_id=self.aws_creds['AccessKeyId'],
                aws_secret_access_key=self.aws_creds['SecretAccessKey'],
                aws_session_token=self.aws_creds['SessionToken']
            )
        else:
            _kms_client = self.kms_client
        try:
            token = _kms_client.encrypt(
                KeyId=self.auth_key,
                Plaintext=payload,
                EncryptionContext=self.auth_context
            )['CiphertextBlob']
            token = base64.b64encode(token)
        except Exception:
            logging.exception('Failed to create auth token.')
            raise TokenCreationError()
        self._cache_token(token, not_after)
        return token

    def _check_response_code(self, response, expected=None):
        if expected is None:
            expected = [200]
        if response.status_code not in expected:
            logging.error('API error (response code {0}): {1}'.format(
                response.status_code,
                response.text
            ))
            return False
        return True

    def get_service(self, service, decrypt_blind=False):
        """Get a service's metadata and secrets."""
        # Return a dict, always with an attribute that specifies whether or not
        # the function was able to successfully get a result.
        ret = {'result': False}
        try:
            # Make a request to confidant with the provided url, to fetch the
            # service providing the service name and base64 encoded
            # token for authentication.
            response = self.request_session.get(
                '{0}/v1/services/{1}'.format(self.url, service),
                auth=(self._get_username(), self._get_token()),
                allow_redirects=False,
                timeout=2
            )
        except requests.ConnectionError:
            logging.error('Failed to connect to confidant.')
            return ret
        except requests.Timeout:
            logging.error('Confidant request timed out.')
            return ret
        if not self._check_response_code(response, expected=[200, 404]):
            return ret
        if response.status_code == 404:
            logging.debug('Service not found in confidant.')
            ret['result'] = True
            return ret
        try:
            data = response.json()
            if decrypt_blind:
                data['blind_credentials'] = self._decrypt_blind_credentials(
                    data['blind_credentials']
                )
        except ValueError:
            logging.error('Received badly formatted json data from confidant.')
            return ret
        ret['service'] = data
        ret['result'] = True
        return ret

    def get_blind_credential(self, id, decrypt_blind=False):
        """Get a blind credential from ID."""
        # Return a dict, always with an attribute that specifies whether or not
        # the function was able to successfully get a result.
        ret = {'result': False}
        try:
            # Make a request to confidant with the provided url, to fetch the
            # service providing the service name and base64 encoded
            # token for authentication.
            response = self.request_session.get(
                '{0}/v1/blind_credentials/{1}'.format(self.url, id),
                auth=(self._get_username(), self._get_token()),
                allow_redirects=False,
                timeout=2
            )
        except requests.ConnectionError:
            logging.error('Failed to connect to confidant.')
            return ret
        except requests.Timeout:
            logging.error('Confidant request timed out.')
            return ret
        if not self._check_response_code(response, expected=[200, 404]):
            return ret
        if response.status_code == 404:
            logging.debug('Blind credential not found in confidant.')
            ret['result'] = False
            return ret
        try:
            data = response.json()
            if decrypt_blind:
                data['decrypted_credential_pairs'] = self._get_decrypted_pairs(
                    data
                )
        except ValueError:
            logging.error('Received badly formatted json data from confidant.')
            return ret
        ret['blind_credential'] = data
        ret['result'] = True
        return ret

    def _decrypt_blind_credentials(self, blind_credentials):
        _blind_credentials = []
        for blind_credential in blind_credentials:
            decrypted_pairs = self._get_decrypted_pairs(
                blind_credential
            )
            blind_credential['decrypted_credential_pairs'] = decrypted_pairs
            _blind_credentials.append(blind_credential)
        return _blind_credentials

    def _get_decrypted_pairs(self, credential):
        """
        From credential, get decrypted blind credential pairs.

        Given a region => data_key dict of data keys, a region => context dict
        of KMS encryption context, a dict of encrypted credential pairs, a
        cipher and a cipher version, return decrypted credential_pairs.
        """
        region = self.kms_client._client_config.region_name
        _context = credential['metadata']['context'][region]
        _data_key = cryptolib.decrypt_datakey(
            base64.b64decode(credential['data_key'][region]),
            _context
        )
        _credential_pair = credential['credential_pairs'][region]
        f = Fernet(_data_key)
        return json.loads(f.decrypt(_credential_pair.encode('utf-8')))

    def _get_keys_and_encrypted_pairs(
            self,
            blind_keys,
            context,
            credential_pairs,
            cipher_type,
            cipher_version
            ):
        """
        Get data keys and encrypted credential_pairs.

        Given a region => kms key dict of blind keys, a region => context dict
        of KMS encryption context, a dict of credential pairs, a cipher and a
        cipher version, generate a dict of region => data keys and a dict of
        region => encrypted credential_pairs and return both in a tuple.
        """
        data_keys = {}
        _credential_pairs = {}
        for region, blind_key in blind_keys.iteritems():
            if self.aws_creds:
                session = confidant.services.get_boto_session(
                    region=region,
                    aws_access_key_id=self.aws_creds['AccessKeyId'],
                    aws_secret_access_key=self.aws_creds['SecretAccessKey'],
                    aws_session_token=self.aws_creds['SessionToken']
                )
            else:
                session = confidant.services.get_boto_session(
                    region=region
                )
            _kms = session.client('kms')
            data_key = cryptolib.create_datakey(
                context[region],
                blind_key,
                _kms
            )
            data_keys[region] = base64.b64encode(data_key['ciphertext'])
            # TODO: this crypto code needs to come from a library. Right now we
            # only support fernet and cipher_version 2, so we're hardcoding it
            # and ignoring the arguments.
            f = Fernet(data_key['plaintext'])
            # For paranoia sake, let's purposely purge plaintext from the
            # data_key, incase someone decides later to include the data_key
            # directly into the return.
            del data_key['plaintext']
            _credential_pairs[region] = f.encrypt(
                json.dumps(credential_pairs).encode('utf-8')
            )
        return data_keys, _credential_pairs

    def create_blind_credential(
            self,
            blind_keys,
            contexts,
            name,
            credential_pairs,
            metadata=None,
            cipher_type='fernet',
            cipher_version=2,
            store_keys=True,
            enabled=True
            ):
        """Create a server blinded credential and store it in Confidant."""
        # Return a dict, always with an attribute that specifies whether or not
        # the function was able to successfully get a result.
        ret = {'result': False}
        if metadata is None:
            metadata = {}
        metadata['context'] = contexts
        data_keys, _credential_pairs = self._get_keys_and_encrypted_pairs(
            blind_keys,
            contexts,
            credential_pairs,
            cipher_type,
            cipher_version
        )
        data = {
            'name': name,
            'credential_pairs': _credential_pairs,
            'data_key': data_keys,
            'metadata': metadata,
            'cipher_type': cipher_type,
            'cipher_version': cipher_version,
            'enabled': enabled
        }
        if store_keys:
            data['credential_keys'] = credential_pairs.keys()
        try:
            response = self.request_session.post(
                '{0}/v1/blind_credentials'.format(self.url),
                auth=(self._get_username(), self._get_token()),
                headers=JSON_HEADERS,
                data=json.dumps(data),
                allow_redirects=False,
                timeout=5
            )
        except requests.ConnectionError:
            logging.error('Failed to connect to confidant.')
            return ret
        except requests.Timeout:
            logging.error('Confidant request timed out.')
            return ret
        if not self._check_response_code(response):
            return ret
        try:
            data = response.json()
        except ValueError:
            logging.error('Received badly formatted json data from confidant.')
            return ret
        ret['blind_credential'] = data
        ret['result'] = True
        return ret

    def update_blind_credential(
            self,
            id,
            blind_keys=None,
            contexts=None,
            name=None,
            credential_pairs=None,
            metadata=None,
            cipher_type=None,
            cipher_version=None,
            store_keys=True,
            enabled=None
            ):
        """Update a server blinded credential in Confidant."""
        # Return a dict, always with an attribute that specifies whether or not
        # the function was able to successfully get a result.
        ret = {'result': False}
        cred = self.get_blind_credential(id)
        if not cred['result']:
            return ret
        data = cred['blind_credential']
        del data['revision']
        del data['modified_by']
        del data['modified_date']
        if name is not None:
            data['name'] = name
        if metadata is not None:
            _context = data['metadata']['context']
            data['metadata'] = metadata
            data['metadata']['context'] = _context
        if credential_pairs is not None:
            if contexts is not None:
                data['metadata']['context'] = contexts
            else:
                contexts = data['metadata']['context']
            if cipher_type is not None:
                data['cipher_type'] = cipher_type
            else:
                cipher_type = data['cipher_type']
            if cipher_version is not None:
                data['cipher_version'] = cipher_version
            else:
                cipher_version = data['cipher_version']
            data_keys, _credential_pairs = self._get_keys_and_encrypted_pairs(
                blind_keys,
                contexts,
                credential_pairs,
                cipher_type,
                cipher_version
            )
            data['data_key'] = data_keys
            data['credential_pairs'] = _credential_pairs
            if store_keys:
                data['credential_keys'] = credential_pairs.keys()
        if enabled is not None:
            data['enabled'] = enabled
        try:
            response = self.request_session.put(
                '{0}/v1/blind_credentials/{1}'.format(self.url, id),
                auth=(self._get_username(), self._get_token()),
                headers=JSON_HEADERS,
                data=json.dumps(data),
                allow_redirects=False,
                timeout=5
            )
        except requests.ConnectionError:
            logging.error('Failed to connect to confidant.')
            return ret
        except requests.Timeout:
            logging.error('Confidant request timed out.')
            return ret
        if not self._check_response_code(response):
            return ret
        try:
            data = response.json()
        except ValueError:
            logging.error('Received badly formatted json data from confidant.')
            return ret
        ret['blind_credential'] = data
        ret['result'] = True
        return ret


class TokenCreationError(Exception):

    """An exception raised when a token was unsuccessfully created."""

    pass


class ClientConfigurationError(Exception):

    """An exception raised when the client has been invalidly configured."""

    pass
