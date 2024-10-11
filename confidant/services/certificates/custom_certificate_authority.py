import logging
from datetime import datetime, timedelta

from cerberus import Validator
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.hashes import SHA256

from confidant.services.certificates.certificate_authority import (
    CertificateAuthorityBase, CertificateAuthorityNotFoundError)
from confidant.settings import (CUSTOM_CA_ACTIVE_KEYS,
                                CUSTOM_CERTIFICATE_AUTHORITIES)

logger = logging.getLogger(__name__)

CUSTOM_CA_SCHEMA = {
    "rootcrt": {"type": "string", "required": True, "nullable": True},
    "crt": {"type": "string", "required": True},
    "key": {"type": "string", "required": True},
    "passphrase": {"type": "string", "required": True, "nullable": True},
    "kid": {"type": "string", "required": True},
}


class CustomCertificateAuthority(CertificateAuthorityBase):
    """Custom Certificate Authority

    Args:
        CertificateAuthorityBase (_type_): Base class for Certificate Authority
    """
    def __init__(self, ca_env: str):
        self.ca_id = ca_env
        self.active_ca_id = None
        self.ca_json = self._get_ca_in_json(ca_env)
        self.ca_certificate = self._load_ca_certificate(self.ca_json)
        self.root_ca_certificate = self._load_rootca_certificate(self.ca_json)
        self.ca_private_key = self._load_private_key(self.ca_json)

    def _get_ca_in_json(self, ca_env: str):
        if (
            not CUSTOM_CERTIFICATE_AUTHORITIES
            or ca_env not in CUSTOM_CERTIFICATE_AUTHORITIES
        ):
            logger.error("Custom CA %s not found", ca_env)
            raise CertificateAuthorityNotFoundError(f"Custom CA {ca_env} not found")
        if not CUSTOM_CA_ACTIVE_KEYS or ca_env not in CUSTOM_CA_ACTIVE_KEYS:
            logger.error("Custom CA %s has no active keys", ca_env)
            raise CertificateAuthorityNotFoundError(
                f"Custom CA {ca_env} has no active keys"
            )
        validator = Validator(CUSTOM_CA_SCHEMA)
        active_ca_id = CUSTOM_CA_ACTIVE_KEYS[ca_env]
        self.active_ca_id = active_ca_id
        active_ca = [
            ca
            for ca in CUSTOM_CERTIFICATE_AUTHORITIES[ca_env]
            if validator.validate(ca) and ca["kid"] == active_ca_id
        ]
        if not active_ca:
            logger.error("Custom CA %s has no active keys", ca_env)
            raise CertificateAuthorityNotFoundError(
                f"Custom CA {ca_env} has no matching valid active keys for {active_ca_id}"
            )
        return active_ca[0]

    def _load_ca_certificate(self, ca_json):
        return x509.load_pem_x509_certificate(ca_json["crt"].encode("utf-8"))


    def _load_rootca_certificate(self, ca_json):
        if "rootcrt" not in ca_json or not ca_json["rootcrt"]:
            logger.warning("Custom CA has no root certificate")
            return None
        return x509.load_pem_x509_certificate(ca_json["rootcrt"].encode("utf-8"))

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

        # Get the certificate in PEM format
        intermediate_ca_pem = self.encode_certificate(self.ca_certificate)
        root_ca_pem = self.encode_certificate(self.root_ca_certificate)

        # Return the certificate in PEM format
        response = {
            "certificate": certificate.public_bytes(serialization.Encoding.PEM).decode('utf-8'),
            "certificate_chain": intermediate_ca_pem.decode('utf-8') + root_ca_pem.decode('utf-8'),
        }
        return response

    def get_certificate_authority_certificate(self):
        intermediate_ca_pem = self.encode_certificate(self.ca_certificate)
        root_ca_pem = self.encode_certificate(self.root_ca_certificate)
        return {
            "ca": self.active_ca_id,
            "certificate": intermediate_ca_pem,
            "certificate_chain": intermediate_ca_pem + root_ca_pem,
            "tags": [],
        }

    def issue_certificate_with_key(self, cn, validity, san=None):
        raise NotImplementedError("Custom CA does not support issuing certificates with key")

    def generate_self_signed_certificate(self, key, cn, validity, san=None):
        raise NotImplementedError("Custom CA does not support generating self signed certificates")

    def generate_key(self):
        raise NotImplementedError("Custom CA does not support generating keys")

    def generate_x509_name(self, cn):
        raise NotImplementedError("Custom CA does not support generating x509 names")
