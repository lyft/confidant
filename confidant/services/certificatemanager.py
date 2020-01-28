import logging
import uuid

import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


import confidant.clients
from confidant import settings

TOKENS = {}


def generate_key():
    key = rsa.generate_private_key(
        public_exponent=settings.ACM_PRIVATE_CA_KEY_PUBLIC_EXPONENT_SIZE,
        key_size=settings.ACM_PRIVATE_CA_KEY_SIZE,
        backend=default_backend()
    )
    return key


def encode_key(key):
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
    )


def generate_x509_name(cn):
    name_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME
            )
        )
    if settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME
            )
        )
    if settings.ACM_PRIVATE_CA_CSR_LOCALITY_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.LOCALITY_NAME,
                settings.LOCALITY_NAME
            )
        )
    if settings.ACM_PRIVATE_CA_CSR_ORGANIZATION_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                settings.ORGANIZATION_NAME
            )
        )
    return x509.Name(name_attributes)


def generate_csr(key, cn, san=None):
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        generate_x509_name(cn)
    )
    if san:
        dns_names = []
        for dns_name in san:
            dns_names.append(x509.DNSName(dns_name))
        csr = csr.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False,
        )
    return csr.sign(key, hashes.SHA256(), default_backend())


def encode_csr(csr):
    return csr.public_bytes(serialization.Encoding.PEM)


def decode_csr(pem_csr):
    return x509.load_pem_x509_csr(pem_csr, default_backend())


def get_csr_common_name(csr):
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cns:
        return cns[0].value
    return None


def get_csr_san(csr):
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = []
    if san:
        for dns_name in san.value:
            dns_names.append(dns_name.value)
    return dns_names


def generate_self_signed_certificate(key, cn, validity, san=None):
    _validity = min(validity, settings.ACM_PRIVATE_CA_MAX_VALIDITY_DAYS)
    subject = generate_x509_name(cn)
    issuer = subject
    cert = x509.CertificateBuilder(
    ).subject_name(
        subject,
    ).issuer_name(
        issuer,
    ).public_key(
        key,
    ).serial_number(
        x509.random_serial_number(),
    ).not_valid_before(
        datetime.datetime.utcnow(),
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=_validity),
    )
    if san:
        dns_names = []
        for dns_name in san:
            dns_names.append(x509.DNSName(dns_name))
        cert = cert.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False,
        )
    return cert.sign(key, hashes.SHA256(), default_backend())


def encode_certificate(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def issue_certificate(csr, validity):
    client = confidant.clients.get_boto_client('acm-pca')
    if csr not in TOKENS:
        TOKENS[csr] = uuid.uuid4()
    response = client.issue_certificate(
        CertificateAuthorityArn=settings.ACM_PRIVATE_CA_ARN,
        Csr=csr,
        SigningAlgorithm=settings.ACM_PRIVATE_CA_SIGNING_ALGORITHM,
        Validity={
            'Value': min(validity, settings.ACM_PRIVATE_CA_MAX_VALIDITY_DAYS),
            'Type': 'DAYS',
        },
        IdempotencyToken=TOKENS[csr],
    )
    return get_certificate_from_arn(response['CertificateArn'])


def issue_and_get_certificate(csr, validity):
    response = get_certificate_from_arn(issue_certificate(csr, validity))
    return {
        'certificate': response['Certificate'],
        'certificate_chain': response['CertificateChain'],
    }


def issue_certificate_with_key(cn, validity, san=None):
    key = generate_key()
    encoded_key = encode_key(key)
    if settings.ACM_PRIVATE_CA_SELF_SIGN:
        cert = encode_certificate(
            generate_self_signed_certificate(key, cn, validity, san)
        )
        return {
            'certificate': cert,
            'certificate_chain': cert,
            'key': encoded_key,
        }
    csr = generate_csr(key, cn, san)
    response = issue_and_get_certificate(csr, validity)
    response['key'] = encoded_key
    return response


def get_certificate_from_arn(certificate_arn):
    client = confidant.clients.get_boto_client('acm-pca')
    response = client.get_certificate(
        CertificateAuthorityArn=settings.ACM_PRIVATE_CA_ARN,
        CertificateArn=certificate_arn,
    )
    return response


def get_certificate_authority_certificate():
    client = confidant.clients.get_boto_client('acm-pca')
    response = client.get_certificate_authority_certificate(
        CertificateAuthorityArn=settings.ACM_PRIVATE_CA_ARN,
    )
    return response
