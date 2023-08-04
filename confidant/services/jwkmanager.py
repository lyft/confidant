import logging
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import jwt
from cerberus import Validator
from confidant.settings import JWT_ACTIVE_SIGNING_KEYS
from confidant.settings import JWT_CACHING_ENABLED
from confidant.settings import JWT_CERTIFICATE_AUTHORITIES
from confidant.settings import JWT_DEFAULT_JWT_EXPIRATION_SECONDS
from confidant.settings import JWT_CACHING_TTL
from confidant.utils import stats
from jwcrypto import jwk


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
        if JWT_CERTIFICATE_AUTHORITIES:
            for environment in JWT_CERTIFICATE_AUTHORITIES:
                for ca in JWT_CERTIFICATE_AUTHORITIES[environment]:
                    if validator.validate(ca):
                        self.set_key(environment, ca['kid'],
                                     ca['key'],
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
                expiration_seconds: int = JWT_DEFAULT_JWT_EXPIRATION_SECONDS,
                algorithm: str = 'RS256') -> str:
        kid, key = self.get_active_key(environment)
        if not key:
            raise ValueError('No active key for this environment')

        user = payload.get('user')
        requester = payload.get('requester')

        if not user:
            raise ValueError('Please include the user in the payload')

        if not requester:
            raise ValueError('Please include the requester in the payload')

        if kid not in self._token_cache:
            self._token_cache[kid] = {}

        if requester not in self._token_cache[kid]:
            self._token_cache[kid][requester] = {}

        now = datetime.now(tz=timezone.utc)

        token = None
        if JWT_CACHING_ENABLED:
            token = self._token_cache[kid][requester].get(user)
            if token:
                token_cache_ttl_diff = (now - token['expiry']).total_seconds()
                if token_cache_ttl_diff < JWT_CACHING_TTL:
                    stats.incr('jwt.get_jwt.cache.hit')
                    token = token['token']
                else:
                    stats.incr('jwt.get_jwt.cache.expired')
                    del self._token_cache[kid][requester][user]
            else:
                stats.incr('jwt.get_jwt.cache.miss')

        # cache miss or disabled
        if not token:
            expiry = now + timedelta(seconds=expiration_seconds)
            payload.update({
                'iat': now,
                'nbf': now,
                'exp': expiry,
            })
            with stats.timer('jwt.get_jwt.encode'):
                token = jwt.encode(
                    payload=payload,
                    headers={'kid': kid},
                    key=key,
                    algorithm=algorithm,
                )
            stats.incr('jwt.get_jwt.create')
            self._token_cache[kid][requester][user] = {
                'expiry': expiry,
                'token': token
            }
        return token

    def get_active_key(self, environment: str) -> Tuple[str, Optional[jwk.JWK]]:
        # The active signing key used to sign JWTs
        if environment in JWT_ACTIVE_SIGNING_KEYS and environment in self._keys:
            kid = JWT_ACTIVE_SIGNING_KEYS[environment]
            stats.incr(f'jwt.get_active_key.{environment}.{kid}')
            return kid, self._get_key(kid, environment)
        return '', None

    def get_jwks(self, environment: str, algorithm: str = 'RS256') \
            -> List[Dict[str, str]]:
        keys = self._keys.get(environment)
        if keys:
            stats.incr(f'jwt.get_jwks.{environment}.hit')
            return [{
                **key.export_public(as_dict=True),
                'alg': algorithm
            } for key in keys]
        else:
            stats.incr(f'jwt.get_jwks.{environment}.miss')
            return []


jwk_manager = JWKManager()
