import hashlib
import time

import datetime

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


import confidant.clients
from confidant import settings


def generate_key():
    """
    Generate and return a private RSA key object
    """
    key = rsa.generate_private_key(
        public_exponent=settings.ACM_PRIVATE_CA_KEY_PUBLIC_EXPONENT_SIZE,
        key_size=settings.ACM_PRIVATE_CA_KEY_SIZE,
        backend=default_backend()
    )
    return key


def encode_key(key):
    """
    Return the PEM encoded version of the provided private RSA key object
    """
    return key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )


def generate_x509_name(cn):
    """
    For the given common name string, generate and return an x509.Name, with
    attributes configured in the settings.
    """
    name_attributes = [
        x509.NameAttribute(NameOID.COMMON_NAME, cn),
    ]
    if settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.COUNTRY_NAME,
                settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME,
            )
        )
    if settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.STATE_OR_PROVINCE_NAME,
                settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME,
            )
        )
    if settings.ACM_PRIVATE_CA_CSR_LOCALITY_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.LOCALITY_NAME,
                settings.ACM_PRIVATE_CA_CSR_LOCALITY_NAME,
            )
        )
    if settings.ACM_PRIVATE_CA_CSR_ORGANIZATION_NAME:
        name_attributes.append(
            x509.NameAttribute(
                NameOID.ORGANIZATION_NAME,
                settings.ACM_PRIVATE_CA_CSR_ORGANIZATION_NAME,
            )
        )
    return x509.Name(name_attributes)


def generate_csr(key, cn, san=None):
    """
    Using the provided rsa key object, a string common name, and a list of
    string subject alternative names, generate and return a csr object.
    """
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        generate_x509_name(cn)
    )
    if san:
        dns_names = encode_san_dns_names(san)
        csr = csr.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False,
        )
    return csr.sign(key, hashes.SHA256(), default_backend())


def encode_csr(csr):
    """
    Return a PEM string encoded version of the csr object.
    """
    return csr.public_bytes(serialization.Encoding.PEM)


def decode_csr(pem_csr):
    """
    Return a csr object from the pem encoded csr.
    """
    return x509.load_pem_x509_csr(pem_csr, default_backend())


def get_csr_common_name(csr):
    """
    From the provided csr object, return the string value of the common
    name attribute.
    """
    cns = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if cns:
        # get_attributes_for_oid returns a list, but there should only be a
        # single cn attribute, so just return the first item.
        return cns[0].value
    return None


def get_csr_san(csr):
    """
    From the provided csr object, return a list of the string values of the
    subjust alternative name extension.
    """
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    dns_names = []
    if san:
        for dns_name in san.value:
            dns_names.append(dns_name.value)
    return dns_names


def encode_san_dns_names(san):
    """
    Return a list of x509.DNSName attributes from a list of strings.
    """
    dns_names = []
    for dns_name in san:
        dns_names.append(x509.DNSName(dns_name))
    return dns_names


def generate_self_signed_certificate(key, cn, validity, san=None):
    """
    Using the provided rsa key, a string common name, a validity (in number
    of days), and a list of subject alternative names (as strings), generate
    and return a signed certificate object.
    """
    _validity = min(validity, settings.ACM_PRIVATE_CA_MAX_VALIDITY_DAYS)
    subject = generate_x509_name(cn)
    issuer = subject
    # x509.CertificateBuilder functions return modified versions of the object,
    # so it's weirdly meant to be chained as function calls, making this look
    # weirdly javascript-like.
    cert = x509.CertificateBuilder(
    ).subject_name(
        subject,
    ).issuer_name(
        issuer,
    ).public_key(
        key.public_key(),
    ).serial_number(
        x509.random_serial_number(),
    ).not_valid_before(
        datetime.datetime.utcnow(),
    ).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=_validity),
    )
    if san:
        dns_names = encode_san_dns_names(san)
        cert = cert.add_extension(
            x509.SubjectAlternativeName(dns_names),
            critical=False,
        )
    return cert.sign(key, hashes.SHA256(), default_backend())


def encode_certificate(cert):
    """
    Return the PEM string encoded version of the certificate object.
    """
    return cert.public_bytes(serialization.Encoding.PEM)


def issue_certificate(csr, validity):
    """
    Given a PEM encoded csr, and a validity for the certificate (in number of
    days), issue a certificate from ACM Private CA, and return the ARN
    of the issued certificate.
    """
    client = confidant.clients.get_boto_client('acm-pca')
    response = client.issue_certificate(
        CertificateAuthorityArn=settings.ACM_PRIVATE_CA_ARN,
        Csr=csr,
        SigningAlgorithm=settings.ACM_PRIVATE_CA_SIGNING_ALGORITHM,
        Validity={
            'Value': min(validity, settings.ACM_PRIVATE_CA_MAX_VALIDITY_DAYS),
            'Type': 'DAYS',
        },
        # Quick/easy idempotent token is just a hash of the csr itself. The
        # token must be 36 chars or less.
        IdempotencyToken=hashlib.sha256(csr).hexdigest()[:36],
    )
    return response['CertificateArn']


def issue_and_get_certificate(csr, validity):
    """
    Given a PEM encoded csr, and a validity for the certificate (in number of
    days), issue a certificate from ACM Private CA, and return a dict with
    the PEM encoded certificate and certificate_chain.
    """
    response = get_certificate_from_arn(issue_certificate(csr, validity))
    return {
        'certificate': response['Certificate'],
        'certificate_chain': response['CertificateChain'],
    }


def issue_certificate_with_key(cn, validity, san=None):
    """
    Given the string common name, the validity length of the certificate (in
    number of days), and a list of subject alternative names, return a dict
    with the PEM encoded certificate, certificate chain, and private RSA key.
    """
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
    response = issue_and_get_certificate(encode_csr(csr), validity)
    response['key'] = encoded_key
    return response


def get_certificate_from_arn(certificate_arn):
    """
    Get the PEM encoded certificate from the provided ARN.
    """
    client = confidant.clients.get_boto_client('acm-pca')
    # When a certificate is issued, it may take a while before it's available
    # via get_certificate. We need to keep retrying until it's fully issued.
    while True:
        try:
            response = client.get_certificate(
                CertificateAuthorityArn=settings.ACM_PRIVATE_CA_ARN,
                CertificateArn=certificate_arn,
            )
            break
        except client.exceptions.RequestInProgressException:
            time.sleep(.200)
    return response


def get_certificate_authority_certificate():
    """
    Return the PEM encoded CA certificate and certificate chain from the CA
    ARN.
    """
    client = confidant.clients.get_boto_client('acm-pca')
    response = client.get_certificate_authority_certificate(
        CertificateAuthorityArn=settings.ACM_PRIVATE_CA_ARN,
    )
    return response
