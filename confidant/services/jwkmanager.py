import logging
import jwt

from jwcrypto import jwk
from typing import Any, Dict, Optional, List
from hashlib import sha1
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from confidant.settings import CERTIFICATE_AUTHORITIES, \
    DEFAULT_JWT_EXPIRATION_SECONDS, JWT_CACHING_ENABLED, ACTIVE_SIGNING_KEYS
from confidant.utils import stats
from datetime import datetime, timezone, timedelta
from cerberus import Validator


logger = logging.getLogger(__name__)

CA_SCHEMA = {
    'crt': {'type': 'string', 'required': True},
    'key': {'type': 'string', 'required': True},
    'passphrase': {'type': 'string', 'required': True},
    'kid': {'type': 'string', 'required': True},
}


class JWKManager:
    def __init__(self) -> None:
        self._keys = {}
        self._public_keys = {}
        self._token_cache = {}
        self._payload_cache = {}

        self._load_certificate_authorities()

    def _load_certificate_authorities(self) -> None:
        validator = Validator(CA_SCHEMA)
        if CERTIFICATE_AUTHORITIES:
            for environment in CERTIFICATE_AUTHORITIES:
                for ca in CERTIFICATE_AUTHORITIES[environment]:
                    if validator.validate(ca):
                        self.set_key(environment, ca['kid'], ca['key'],
                                     passphrase=ca['passphrase'])
                    else:
                        logger.error(f'Invalid entry in {environment} in CERTIFICATE_AUTHORITIES')

    def set_key(self, environment: str, kid: str,
                private_key: str,
                passphrase: Optional[str] = None,
                encoding: str = 'utf-8') -> str:
        if environment not in self._keys:
            self._keys[environment] = jwk.JWKSet()

        if passphrase:
            passphrase = passphrase.encode(encoding)
        key = jwk.JWK()
        key.import_from_pem(private_key.encode(encoding),
                            password=passphrase, kid=kid)
        if not self._keys[environment].get_key(kid):
            self._keys[environment].add(key)
        return kid

    def get_jwt(self, environment: str, payload: dict,
                expiration_seconds: int = DEFAULT_JWT_EXPIRATION_SECONDS,
                algorithm: str = 'RS256') -> str:
        key = self.get_active_key(environment)
        if not key:
            raise ValueError('No active key for this environment')

        if 'user' not in payload:
            raise ValueError('Please include the user in the payload')

        if key.key_id not in self._token_cache:
            self._token_cache[key.key_id] = {}

        user = payload['user']
        now = datetime.now(tz=timezone.utc)

        # return token from cache
        if user in self._token_cache[key.key_id].keys() \
                and JWT_CACHING_ENABLED:
            if now < self._token_cache[key.key_id][user]['expiry']:
                stats.incr('get_jwt.cache.hit')
                return self._token_cache[key.key_id][user]['token']

        # cache miss, generate new token and update cache
        expiry = now + timedelta(seconds=expiration_seconds)
        payload.update({
            'iat': now,
            'nbf': now,
            'exp': expiry,
        })

        with stats.timer('get_jwt.encode'):
            # XXX: TODO: cache export_to_pem
            token = jwt.encode(
                payload=payload,
                headers={'kid': key.key_id},
                key=key.export_to_pem(private_key=True, password=None),
                algorithm=algorithm,
            )

        self._token_cache[key.key_id][user] = {
            'expiry': expiry,
            'token': token
        }
        stats.incr('get_jwt.create')
        return token

    def _get_public_key(self, alias: str, certificate: str,
                        encoding: str = 'utf-8') -> bytes:
        if alias not in self._public_keys:
            imported_cert = load_pem_x509_certificate(
                certificate.encode(encoding)
            )
            public_key = imported_cert.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
            self._public_keys[alias] = public_key
        return self._public_keys[alias]

    def get_payload(self, certificate: str, token: str,
                    encoding: str = 'utf-8') -> Dict[str, Any]:
        certificate_hash = sha1(certificate.encode('utf-8')).hexdigest()
        public_key = self._get_public_key(certificate_hash, certificate,
                                          encoding=encoding)
        token_hash = sha1(token.encode('utf-8')).hexdigest()

        if certificate_hash not in self._payload_cache:
            self._payload_cache[certificate_hash] = {}

        if token_hash not in self._payload_cache[certificate_hash]:
            headers = jwt.get_unverified_header(token)
            self._payload_cache[certificate_hash][token_hash] = \
                jwt.decode(token, public_key, algorithms=headers['alg'])

        return self._payload_cache[certificate_hash][token_hash]

    def get_active_key(self, environment: str) -> jwk.JWK:
        if environment in ACTIVE_SIGNING_KEYS and environment in self._keys:
            return self._keys[environment].get_key(
                ACTIVE_SIGNING_KEYS[environment]
            )

    def get_jwks(self, environment: str, algorithm: str = 'RS256') \
            -> List[Dict[str, str]]:
        keys = self._keys.get(environment)
        if keys:
            stats.incr(f'get_jwks.{environment}.hit')
            return [{
                **key.export_public(as_dict=True),
                'alg': algorithm
            } for key in keys]
        else:
            stats.incr(f'get_jwks.{environment}.miss')
            return []


jwk_manager = JWKManager()
