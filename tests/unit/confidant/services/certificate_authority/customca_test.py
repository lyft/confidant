import pytest
from unittest.mock import patch

from confidant.services.certificate_authority.certificateauthoritybase import (
    CertificateAuthorityNotFoundError,
)
from confidant.services.certificate_authority.customca import (
    CustomCertificateAuthority,
)
from tests.conftest import TEST_CERTIFICATE
from cryptography.hazmat.primitives import serialization
from cryptography import x509
from datetime import datetime, timedelta, timezone
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.hashes import SHA256


@pytest.fixture
@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def ca_authority():
    # Mock the CA private key and certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    certificate = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")]
            )
        )
        .issuer_name(
            x509.Name(
                [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "Test CA")]
            )
        )
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(timezone.utc))
        .not_valid_after(datetime.now(timezone.utc) + timedelta(days=365))
        .public_key(private_key.public_key())
        .sign(private_key, SHA256())
    )

    ca = CustomCertificateAuthority("test")
    ca.ca_private_key = private_key
    ca.ca_certificate = certificate
    ca.ca_chain = []  # Mock CA chain for simplicity
    ca.settings = {"max_validity_days": 30}

    return ca


def mock_constants():
    return {
        "CUSTOM_CA_ACTIVE_KEYS": {"test": "test1"},
        "CUSTOM_CERTIFICATE_AUTHORITIES": {
            "test": [
                {
                    "rootcrt": TEST_CERTIFICATE.decode("utf-8"),
                    "crt": "CERTIFICATE",
                    "key": "KEY",
                    "passphrase": "DOG-AND-FRIENDS",
                    "kid": "test1",
                },
            ],
            "invalid": [],
        },
        "CUSTOM_CERTIFICATE_AUTHORITIES_INVALID_SCHEMA": {
            "test": [
                {
                    "invalid_field": "invalid",
                    "crt": "CERTIFICATE",
                    "passphrase": "DOG-AND-FRIENDS",
                },
            ],
        },
        "CUSTOM_CA_SCHEMA": {},
    }


@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CA_ACTIVE_KEYS",
    mock_constants()["CUSTOM_CA_ACTIVE_KEYS"],
)
@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CERTIFICATE_AUTHORITIES",  # noqa: E501
    mock_constants()["CUSTOM_CERTIFICATE_AUTHORITIES"],
)
@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def test_get_ca_in_json_non_existent():
    ca_object = CustomCertificateAuthority("test")
    with pytest.raises(CertificateAuthorityNotFoundError):
        ca_object._get_ca_in_json("nonexistent")


@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CA_ACTIVE_KEYS",
    {},
    # intentionally left blank so that active key
    # does not exist for 'test' environment
)
@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CERTIFICATE_AUTHORITIES",  # noqa: E501
    mock_constants()["CUSTOM_CERTIFICATE_AUTHORITIES"],
)
@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def test_get_ca_in_json_non_existent_active_key():
    ca_object = CustomCertificateAuthority("test")
    with pytest.raises(CertificateAuthorityNotFoundError):
        ca_object._get_ca_in_json("test")


@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CA_ACTIVE_KEYS",
    mock_constants()["CUSTOM_CA_ACTIVE_KEYS"],
)
@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CERTIFICATE_AUTHORITIES",  # noqa: E501
    mock_constants()["CUSTOM_CERTIFICATE_AUTHORITIES_INVALID_SCHEMA"],
)
@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def test_get_ca_in_json_wrong_schema():
    ca_object = CustomCertificateAuthority("test")
    with pytest.raises(CertificateAuthorityNotFoundError):
        ca_object._get_ca_in_json("test")


@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CA_ACTIVE_KEYS",
    mock_constants()["CUSTOM_CA_ACTIVE_KEYS"],
)
@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CERTIFICATE_AUTHORITIES",  # noqa: E501
    mock_constants()["CUSTOM_CERTIFICATE_AUTHORITIES"],
)
@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def test_get_ca_in_json_success():
    ca_object = CustomCertificateAuthority("test")
    response = ca_object._get_ca_in_json("test")
    assert (
        response
        == mock_constants()["CUSTOM_CERTIFICATE_AUTHORITIES"]["test"][0]
    )


@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def test_load_rootca_certificate_success():
    ca_object = CustomCertificateAuthority("test")
    response = ca_object._load_rootca_certificate(
        mock_constants()["CUSTOM_CERTIFICATE_AUTHORITIES"]["test"][0]
    )
    assert response is not None


@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CA_ACTIVE_KEYS",
    mock_constants()["CUSTOM_CA_ACTIVE_KEYS"],
)
@patch(
    "confidant.services.certificate_authority.customca.CUSTOM_CERTIFICATE_AUTHORITIES",  # noqa: E501
    {},
)
@patch.object(
    CustomCertificateAuthority, "__init__", lambda self, ca_env: None
)
def test_load_rootca_certificate_no_root_ca_provided():
    ca_object = CustomCertificateAuthority("test")
    response = ca_object._load_rootca_certificate({})
    assert response is None


def test_issue_certificate_invalid_csr(ca_authority):
    # Generate an invalid private key and CSR
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    subject = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com")]
    )

    # purposely not adding a subject alternative name
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .sign(private_key, SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")

    # Issue the certificate
    with pytest.raises(ValueError):
        ca_authority.issue_certificate(csr_pem, validity=30)


def test_issue_certificate_valid_csr(ca_authority):
    # Generate a valid private key and CSR
    private_key = rsa.generate_private_key(
        public_exponent=65537, key_size=2048
    )
    subject = x509.Name(
        [x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com")]
    )

    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(subject)
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("test1.com"), x509.DNSName("test2.com")]
            ),
            False,
        )
        .sign(private_key, SHA256())
    )
    csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    print(csr_pem)

    # Issue the certificate
    response = ca_authority.issue_certificate(csr_pem, validity=30)

    # Assert the response contains the expected fields
    assert "certificate" in response
    assert "certificate_chain" in response

    # Load the certificate to validate its structure
    issued_cert = x509.load_pem_x509_certificate(
        response["certificate"].encode("utf-8")
    )

    # Assert the issued certificate is valid
    assert issued_cert.subject == subject
    assert issued_cert.issuer == ca_authority.ca_certificate.subject

    # validate SAN
    assert issued_cert.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName) == ["test1.com", "test2.com"]
