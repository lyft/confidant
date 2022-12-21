import logging
import jwt

from jwcrypto import jwk
from typing import Dict, Optional, List, Tuple

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
        self._token_cache = {}
        self._pem_cache = {}

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
                        logger.error(f'Invalid entry in {environment} '
                                     f'in CERTIFICATE_AUTHORITIES')

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

    def _get_key(self, kid: str, environment: str):
        if environment not in self._pem_cache:
            self._pem_cache[environment] = {}

        if kid not in self._pem_cache[environment]:
            # setting either way to avoid further lookups when response is None
            self._pem_cache[environment][kid] = \
                self._keys[environment].get_key(kid)
            if self._pem_cache[environment][kid]:
                self._pem_cache[environment][kid] = \
                    self._pem_cache[environment][kid].export_to_pem(
                    private_key=True,
                    password=None
                )
        return self._pem_cache[environment][kid]

    def get_jwt(self, environment: str, payload: dict,
                expiration_seconds: int = DEFAULT_JWT_EXPIRATION_SECONDS,
                algorithm: str = 'RS256') -> str:
        kid, key = self.get_active_key(environment)
        if not key:
            raise ValueError('No active key for this environment')

        if 'user' not in payload:
            raise ValueError('Please include the user in the payload')

        if kid not in self._token_cache:
            self._token_cache[kid] = {}

        user = payload['user']
        now = datetime.now(tz=timezone.utc)

        # return token from cache
        if user in self._token_cache[kid].keys() \
                and JWT_CACHING_ENABLED:
            if now < self._token_cache[kid][user]['expiry']:
                stats.incr('get_jwt.cache.hit')
                return self._token_cache[kid][user]['token']

        # cache miss, generate new token and update cache
        expiry = now + timedelta(seconds=expiration_seconds)
        payload.update({
            'iat': now,
            'nbf': now,
            'exp': expiry,
        })

        with stats.timer('get_jwt.encode'):
            token = jwt.encode(
                payload=payload,
                headers={'kid': kid},
                key=key,
                algorithm=algorithm,
            )

        self._token_cache[kid][user] = {
            'expiry': expiry,
            'token': token
        }
        stats.incr('get_jwt.create')
        return token

    def get_active_key(self, environment: str) -> Tuple[str, Optional[jwk.JWK]]:
        if environment in ACTIVE_SIGNING_KEYS and environment in self._keys:
            return ACTIVE_SIGNING_KEYS[environment], self._get_key(
                ACTIVE_SIGNING_KEYS[environment],
                environment
            )
        return '', None

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
