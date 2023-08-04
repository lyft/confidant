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
from confidant.settings import JWT_CACHING_TTL_SECONDS

from confidant.utils import stats
from jwcrypto import jwk


logger = logging.getLogger(__name__)

CA_SCHEMA = {
    'crt': {'type': 'string', 'required': True},
    'key': {'type': 'string', 'required': True},
    'passphrase': {'type': 'string', 'required': True, 'nullable': True},
    'kid': {'type': 'string', 'required': True},
}


class JWKManager:
    def __init__(self) -> None:
        self._keys = {}
        self._token_cache = {}
        self._pem_cache = {}

        self._load_certificate_authorities()

        # format of local cache:
        # {
        #     "<kid>": {
        #         "<downstream_requester>": {
        #            "<requested_resource_id>": {
        #                "expiry": 1234567890,
        #                "jwt": "eyJpc19zZ...",
        #         },
        #         ...
        #     },
        #     ...
        # }
        # Example:
        # {
        #     "0h7R8..": {
        #         "serviceA-staging-iad": {
        #             "ServiceAA-staging-iad": {
        #                 "expiry": 1234567890,
        #                 "jwt": "eyJpc19zZX...",
        #         },
        #         ...
        #     },
        #     ...
        # }
        # for kid in self._get_active_kids():
        #     self._token_cache[kid] = {}

        # XXX: TODO, add setting to allow switching between
        # remote redis and local memory cache
        self._get_jwt_cache = self._get_jwt_cache_mem
        self._set_jwt_cache = self._set_jwt_cache_mem

    def _load_certificate_authorities(self) -> None:
        validator = Validator(CA_SCHEMA)
        if JWT_CERTIFICATE_AUTHORITIES:
            for environment in JWT_CERTIFICATE_AUTHORITIES:
                for ca in JWT_CERTIFICATE_AUTHORITIES[environment]:
                    if validator.validate(ca):
                        self.set_key(environment,
                                     ca['kid'],
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

    def _get_active_kids(self) -> List[str]:
        return list(JWT_ACTIVE_SIGNING_KEYS.values())

    def get_jwt(self, environment: str,
                payload: dict,
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

        jwt_str = None
        if JWT_CACHING_ENABLED:
            jwt_str = self._get_jwt_cache(kid, requester, user)
            if jwt_str:
                stats.incr('jwt.get_jwt.cache.hit')
            else:
                stats.incr('jwt.get_jwt.cache.miss')

        # cache miss, create a new jwt
        if not jwt_str:
            now = datetime.now(tz=timezone.utc)
            expiry = now + timedelta(seconds=expiration_seconds)
            payload.update({
                'iat': now,
                'nbf': now,
                'exp': expiry,
            })
            with stats.timer('jwt.get_jwt.encode'):
                jwt_str = jwt.encode(
                    payload=payload,
                    headers={'kid': kid},
                    key=key,
                    algorithm=algorithm,
                )
            stats.incr('jwt.get_jwt.create')
            if JWT_CACHING_ENABLED:
                self._set_jwt_cache(kid, requester, user, expiry, jwt_str)

        return jwt_str

    def _set_jwt_cache_mem(self, kid: str, requester: str, user: str,
                           expiry: str, jwt: str) -> None:

        if kid not in self._token_cache:
            self._token_cache[kid] = {}

        if requester not in self._token_cache[kid]:
            self._token_cache[kid][requester] = {}

        self._token_cache[kid][requester][user] = {
            'expiry': expiry,
            'jwt': jwt
        }

    def _get_jwt_cache_mem(self, kid: str, requester: str, user: str) -> str:
        jwt_str = None
        token_kv = self._token_cache.get(kid, {}).get(requester, {}).get(user)
        if token_kv:
            now = datetime.now(tz=timezone.utc)
            token_cache_ttl_diff = (token_kv['expiry'] - now).total_seconds()
            if token_cache_ttl_diff > JWT_CACHING_TTL_SECONDS:
                stats.incr('jwt.get_jwt.cache.hit')
                jwt_str = token_kv['jwt']
            else:
                stats.incr('jwt.get_jwt.cache.expired')
                del self._token_cache[kid][requester][user]
        else:
            stats.incr('jwt.get_jwt.cache.miss')
        return jwt_str

    def _set_jwt_cache_redis(self, kid: str, requester: str, user: str,
                             expiry: str, jwt: str) -> None:
        # XXX: TODO: place holder for remote redis cache calls
        pass

    def _get_jwt_cache_redis(self, kid: str, requester: str, user: str) -> str:
        # XXX: TODO: place holder for remote redis cache calls
        return ""

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
