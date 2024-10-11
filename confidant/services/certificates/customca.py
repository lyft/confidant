import logging
import json
import hashlib
import time
from abc import ABC, abstractmethod
from cerberus import Validator
from typing import List
from cryptography import x509
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from confidant.services.certificates.certificate_authority import (
    CertificateAuthority,
    CertificateAuthorityNotFoundError,
)
from confidant.settings import CUSTOM_CA_ACTIVE_KEYS
from confidant.settings import CUSTOM_CERTIFICATE_AUTHORITIES
from confidant.utils import stats
from confidant import settings

logger = logging.getLogger(__name__)

CA_SCHEMA = {
    "crt": {"type": "string", "required": True},
    "key": {"type": "string", "required": True},
    "passphrase": {"type": "string", "required": True, "nullable": True},
    "kid": {"type": "string", "required": True},
}


class CustomCertificateAuthority(CertificateAuthority):
    def __init__(self, id: str):
        self.id = id
        self.active_ca_id = None
        self.ca_json = self._get_ca_in_json(id)
        self.ca_certificate = self._load_ca_certificate(self.ca_json)
        self.ca_private_key = self._load_private_key(self.ca_json)

    def _get_ca_in_json(self, id: str):
        if (
            not CUSTOM_CERTIFICATE_AUTHORITIES
            or id not in CUSTOM_CERTIFICATE_AUTHORITIES
        ):
            logger.error(f"Custom CA {id} not found")
            raise CertificateAuthorityNotFoundError(f"Custom CA {id} not found")
        if not CUSTOM_CA_ACTIVE_KEYS or id not in CUSTOM_CA_ACTIVE_KEYS:
            logger.error(f"Custom CA {id} has no active keys")
            raise CertificateAuthorityNotFoundError(
                f"Custom CA {id} has no active keys"
            )
        validator = Validator(CA_SCHEMA)
        active_ca_id = CUSTOM_CA_ACTIVE_KEYS[id]
        self.active_ca_id = active_ca_id
        active_ca = [
            ca
            for ca in CUSTOM_CERTIFICATE_AUTHORITIES[id]
            if validator.validate(ca) and ca["kid"] == active_ca_id
        ]
        if not active_ca:
            logger.error(f"Custom CA {id} has no active keys")
            raise CertificateAuthorityNotFoundError(
                f"Custom CA {id} has no matching valid active keys for {active_ca_id}"
            )
        print(active_ca[0])
        return active_ca[0]

    def _load_ca_certificate(self, ca_json):
        return x509.load_pem_x509_certificate(ca_json["crt"].encode("utf-8"))

    def _load_private_key(self, ca_json):
        private_key = serialization.load_pem_private_key(
            ca_json["key"].encode("utf-8"),
            password=ca_json["passphrase"].encode("utf-8"),
        )
        return private_key

    def issue_certificate(self, csr_pem, validity):
        # Load the CSR from PEM format
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))

        # Verify the CSR
        if not csr.is_signature_valid:
            raise ValueError("Invalid CSR signature")

        # Define the certificate builder using information from the CSR
        builder = x509.CertificateBuilder()
        builder = builder.subject_name(csr.subject)
        builder = builder.issuer_name(self.ca_certificate.subject)  # Issued by our CA
        builder = builder.public_key(csr.public_key())
        builder = builder.serial_number(x509.random_serial_number())
        builder = builder.not_valid_before(datetime.utcnow())
        # TODO: replace with validity from request
        builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=30))

        # Add some extensions (optional)
        builder = builder.add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName(
                csr.extensions.get_extension_for_class(
                    x509.SubjectAlternativeName
                ).value
            ),
            critical=False,
        )

        # Sign the certificate with the CA's private key
        certificate = builder.sign(private_key=self.ca_private_key, algorithm=SHA256())

        # Return the certificate in PEM format
        response = {
            "certificate": certificate.public_bytes(serialization.Encoding.PEM),
            "certificate_chain": self.ca_certificate.public_bytes(
                serialization.Encoding.PEM
            ),
        }
        return response

    def get_certificate_authority_certificate(self):
        ca_certificate_pem = self.ca_certificate.public_bytes(
            encoding=serialization.Encoding.PEM
        )
        ca_certificate_str = ca_certificate_pem.decode("utf-8")
        return {
            "ca": self.active_ca_id,
            "certificate": ca_certificate_str,
            "certificate_chain": ca_certificate_str,
            "tags": [],
        }
