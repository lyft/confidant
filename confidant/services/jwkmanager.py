import jwt

from jwcrypto import jwk
from typing import Dict, Optional
from confidant.settings import CERTIFICATE_AUTHORITIES, \
    DEFAULT_JWT_EXPIRATION_SECONDS, JWT_CACHING_ENABLED
from confidant.utils import stats
from datetime import datetime, timezone, timedelta


class JWKManager:
    def __init__(self) -> None:
        self._keys = jwk.JWKSet()
        self._token_cache = {}
        self._pem_cache = {}

        self._load_certificate_authorities()

    def _load_certificate_authorities(self) -> None:
        if CERTIFICATE_AUTHORITIES:
            for ca in CERTIFICATE_AUTHORITIES:
                self.set_key(ca['name'], ca['key'],
                             passphrase=ca['passphrase'])

    def set_key(self, kid: str, private_key: str,
                passphrase: Optional[str] = None,
                encoding: str = 'utf-8') -> str:
        if passphrase:
            passphrase = passphrase.encode(encoding)
        key = jwk.JWK()
        key.import_from_pem(private_key.encode(encoding),
                            password=passphrase, kid=kid)
        if not self._keys.get_key(kid):
            self._keys.add(key)
        return kid

    def _get_key(self, kid: str):
        if kid not in self._pem_cache:
            # setting either way to avoid further lookups when response is None
            self._pem_cache[kid] = self._keys.get_key(kid)
            if self._pem_cache[kid]:
                self._pem_cache[kid] = self._pem_cache[kid].export_to_pem(
                    private_key=True,
                    password=None
                )
        return self._pem_cache[kid]

    def get_jwt(self, kid: str, payload: dict,
                expiration_seconds: int = DEFAULT_JWT_EXPIRATION_SECONDS,
                algorithm: str = 'RS256') -> str:
        key = self._get_key(kid)
        if not key:
            raise ValueError('This private key is not stored!')

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

    def get_jwks(self, key_id: str, algorithm: str = 'RS256') -> Dict[str, str]:
        key = self._keys.get_key(key_id)
        if key:
            stats.incr(f'get_jwks.{key_id}.hit')
            return {**key.export_public(as_dict=True), 'alg': algorithm}
        else:
            stats.incr(f'get_jwks.{key_id}.miss')
            return {}


jwk_manager = JWKManager()
