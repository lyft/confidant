import logging
from datetime import datetime
from datetime import timedelta
from datetime import timezone
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple

import jwt
from abc import ABC, abstractmethod
from cerberus import Validator
from confidant.settings import JWT_ACTIVE_SIGNING_KEYS
from confidant.settings import JWT_CACHING_ENABLED
from confidant.settings import JWT_CERTIFICATE_AUTHORITIES
from confidant.settings import JWT_DEFAULT_JWT_EXPIRATION_SECONDS
from confidant.settings import JWT_CACHING_MAX_SIZE
from confidant.settings import JWT_CACHING_TTL_SECONDS
from confidant.settings import REDIS_URL_JWT_CACHE, REDIS_SOCKET_TIMEOUT
from confidant.settings import JWT_CACHING_USE_REDIS
from confidant.utils import stats

from redis import StrictRedis, RedisError
from cachetools import TTLCache
from jwcrypto import jwk

logger = logging.getLogger(__name__)

CA_SCHEMA = {
    'crt': {'type': 'string', 'required': True},
    'key': {'type': 'string', 'required': True},
    'passphrase': {'type': 'string', 'required': True, 'nullable': True},
    'kid': {'type': 'string', 'required': True},
}


class JwtCache(ABC):

    @abstractmethod
    def get_jwt(self, kid: str, requester: str, user: str) -> str:
        raise NotImplementedError()

    @abstractmethod
    def set_jwt(self, kid: str, requester: str, user: str, jwt: str) -> None:
        raise NotImplementedError()


class LocalJwtCache(JwtCache):
    def __init__(self) -> None:
        self._token_cache = TTLCache(
            maxsize=JWT_CACHING_MAX_SIZE,
            ttl=JWT_CACHING_TTL_SECONDS
        )

    def cache_key(self, kid: str, requester: str, user: str) -> str:
        return f'{kid}:{requester}:{user}'

    def get_jwt(self, kid: str, requester: str, user: str) -> str:
        cached_jwt = self._token_cache.get(self.cache_key(kid, requester, user))
        return cached_jwt

    def set_jwt(self, kid: str, requester: str, user: str, jwt: str) -> None:
        self._token_cache[self.cache_key(kid, requester, user)] = jwt


class RedisCache(JwtCache):
    def __init__(self) -> None:
        self._redis_client = None
        try:
            self._redis_client = \
                StrictRedis.from_url(REDIS_URL_JWT_CACHE, decode_responses=True,
                                     socket_timeout=REDIS_SOCKET_TIMEOUT)
        except RedisError as e:
            logger.error(f'Failed to setup connection to Redis: {e}')

    def cache_key(self, kid: str, requester: str, user: str) -> str:
        return f'{kid}:{requester}:{user}'

    def get_jwt(self, kid: str, requester: str, user: str) -> str:
        if self._redis_client:
            try:
                cached_jwt = \
                    self._redis_client.get(self.cache_key(kid, requester, user))
            except RedisError as e:
                logger.error(f'Error connecting to Redis: {e}')
                return None
            return cached_jwt

    def set_jwt(self, kid: str, requester: str, user: str, jwt: str) -> None:
        if self._redis_client:
            try:
                self._redis_client.set(self.cache_key(kid, requester, user),
                                       jwt, JWT_CACHING_TTL_SECONDS)
            except RedisError as e:
                logger.error(f'Error connecting to Redis: {e}')
                return None


class JWKManager:
    def __init__(self) -> None:
        self._keys = {}
        self._jwt_cache = None
        if JWT_CACHING_USE_REDIS:
            self._jwt_cache = RedisCache()
        else:
            self._jwt_cache = LocalJwtCache()
        self._pem_cache = {}

        self._load_certificate_authorities()

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
            jwt_str = self._jwt_cache.get_jwt(kid, requester, user)
            if jwt_str:
                stats.incr(f'jwt.get_jwt.cache.{kid}.{requester}.hit')
            else:
                stats.incr(f'jwt.get_jwt.cache.{kid}.{requester}.miss')

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
            stats.incr(f'jwt.get_jwt.{kid}.{requester}.create')
            if JWT_CACHING_ENABLED:
                self._jwt_cache.set_jwt(kid, requester, user, jwt_str)

        return jwt_str

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
