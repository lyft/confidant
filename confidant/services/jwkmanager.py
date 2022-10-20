import jwt

from jwcrypto import jwk
from typing import Any, Dict, Optional
from hashlib import sha1
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from confidant.settings import CERTIFICATE_AUTHORITIES, \
    DEFAULT_JWT_EXPIRATION_SECONDS, JWT_CACHING_ENABLED
from datetime import datetime, timezone, timedelta


class JWKManager:
    def __init__(self) -> None:
        self._keys = jwk.JWKSet()
        self._public_keys = {}
        self._token_cache = {}
        self._payload_cache = {}

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

    def get_jwt(self, kid: str, payload: dict,
                expiration_seconds: int = DEFAULT_JWT_EXPIRATION_SECONDS,
                algorithm: str = 'RS256') -> str:
        key = self._keys.get_key(kid)
        if not key:
            raise ValueError('This private key is not stored!')

        if 'user' not in payload:
            raise ValueError('Please include the user in the payload')

        if kid not in self._token_cache:
            self._token_cache[kid] = {}

        now = datetime.now(tz=timezone.utc)
        if payload['user'] in self._token_cache[kid].keys() \
                and JWT_CACHING_ENABLED:
            if now < self._token_cache[kid][payload['user']]['expiry']:
                return self._token_cache[kid][payload['user']]['token']

        expiry = now + timedelta(seconds=expiration_seconds)
        payload.update({
            'iat': now,
            'nbf': now,
            'exp': expiry,
        })

        self._token_cache[kid][payload['user']] = {}
        self._token_cache[kid][payload['user']]['expiry'] = expiry
        self._token_cache[kid][payload['user']]['token'] = jwt.encode(
            payload=payload,
            headers={'kid': kid},
            key=key.export_to_pem(private_key=True, password=None),
            algorithm=algorithm,
        )
        return self._token_cache[kid][payload['user']]['token']

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

    def get_jwks(self, key_id: str, algorithm: str = 'RS256') -> Dict[str, str]:
        key = self._keys.get_key(key_id)
        if key:
            return {**key.export_public(as_dict=True), 'alg': algorithm}
        else:
            return {}


jwk_manager = JWKManager()
