import jwt
import json

from jwcrypto import jwk
from typing import Any, Dict, Optional
from hashlib import sha1
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import serialization
from confidant.settings import CERTIFICATE_AUTHORITIES


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
                self.set_key(ca['name'], ca['key'], passphrase=ca['passphrase'])

    def set_key(self, kid: str, private_key: str, passphrase: Optional[str] = None, encoding: str = 'utf-8') -> str:
        if passphrase:
            passphrase = passphrase.encode(encoding)
        key = jwk.JWK()
        key.import_from_pem(private_key.encode(encoding), password=passphrase, kid=kid)
        if not self._keys.get_key(kid):
            self._keys.add(key)
        return kid

    def get_jwt(self, kid: str, payload: dict) -> str:
        key = self._keys.get_key(kid)
        if not key:
            raise ValueError('This private key is not stored!')

        payload_hash = sha1(json.dumps(payload, sort_keys=True).encode('utf-8')).hexdigest()
        if kid not in self._token_cache:
            self._token_cache[kid] = {}

        if payload_hash not in self._token_cache[kid]:
            self._token_cache[kid][payload_hash] = jwt.encode(
                payload=payload,
                headers={'kid': kid},
                key=key.export_to_pem(private_key=True, password=None),
                algorithm='RS256',
            )

        return self._token_cache[kid][payload_hash]

    def _get_public_key(self, alias: str, certificate: str, encoding: str = 'utf-8') -> bytes:
        if alias not in self._public_keys:
            imported_cert = load_pem_x509_certificate(certificate.encode(encoding))
            public_key = imported_cert.public_key().public_bytes(encoding=serialization.Encoding.PEM,
                                                                 format=serialization.PublicFormat.SubjectPublicKeyInfo)
            self._public_keys[alias] = public_key
        return self._public_keys[alias]

    def get_payload(self, certificate: str, token: str, encoding: str = 'utf-8') -> Dict[str, Any]:
        certificate_hash = sha1(certificate.encode('utf-8')).hexdigest()
        public_key = self._get_public_key(certificate_hash, certificate, encoding=encoding)
        token_hash = sha1(token.encode('utf-8')).hexdigest()

        if certificate_hash not in self._payload_cache:
            self._payload_cache[certificate_hash] = {}

        if token_hash not in self._payload_cache[certificate_hash]:
            self._payload_cache[certificate_hash][token_hash] = jwt.decode(token, public_key, algorithms=['RS256'])

        return self._payload_cache[certificate_hash][token_hash]


jwk_manager = JWKManager()
