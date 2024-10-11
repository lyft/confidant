import logging
from abc import ABC, abstractmethod

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.x509.oid import NameOID

logger = logging.getLogger(__name__)


class CertificateAuthorityNotFoundError(Exception):
    """
    Exception raised when a specified certificate authority is not found.
    """
    def __init__(self, message="Certificate Authority not found."):
        self.message = message
        super().__init__(self.message)

class CertificateNotReadyError(Exception):
    """
    Exception raised when a certificate is not ready.
    """
    def __init__(self, message="Certificate Authority not ready."):
        self.message = message
        super().__init__(self.message)


class CertificateAuthorityBase(ABC):
    """Base class for certificate authorities.
    """
    @abstractmethod
    def __init__(self, ca: str):
        pass
    
    @abstractmethod
    def issue_certificate(self, csr_pem, validity):
        """
        Given a PEM encoded csr, and a validity for the certificate (in number
        of days), issue a certificate from ACM Private CA, and return the ARN
        of the issued certificate.
        """
        pass
    
    @abstractmethod
    def issue_certificate_with_key(self, cn, validity, san=None):
        """
        Given the string common name, the validity length of the certificate (in
        number of days), and a list of subject alternative names, return a dict
        with the PEM encoded certificate, certificate chain, and private RSA
        key.
        """
        pass
    
    @abstractmethod
    def generate_self_signed_certificate(self, key, cn, validity, san=None):
        """
        Using the provided rsa key, a string common name, a validity (in number
        of days), and a list of subject alternative names (as strings), generate
        and return a signed certificate object.
        """
        pass
    
    @abstractmethod
    def get_certificate_authority_certificate(self):
        """
        Return the PEM encoded CA certificate and certificate chain
        """
        pass

    @abstractmethod
    def generate_key(self):
        """
        Generate and return a private RSA key object
        """
        pass

    @abstractmethod
    def generate_x509_name(self, cn):
        """
        For the given common name string, generate and return an x509.Name, with
        attributes configured in the settings.
        """
        pass
    
    def encode_csr(self, csr):
        """
        Return a PEM string encoded version of the csr object.
        """
        return csr.public_bytes(
            serialization.Encoding.PEM,
        ).decode(encoding="UTF-8")
    
    def decode_csr(self, pem_csr):
        """
        Return a csr object from the pem encoded csr.
        """
        pem_csr = pem_csr.encode(encoding="UTF-8")
        return x509.load_pem_x509_csr(pem_csr, default_backend())
    
    def get_csr_common_name(self, csr):
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

    def get_csr_san(self, csr):
        """
        From the provided csr object, return a list of the string values of the
        subjust alternative name extension.
        """
        dns_names = []
        try:
            san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        except ExtensionNotFound:
            san = None
        if san:
            for dns_name in san.value:
                dns_names.append(dns_name.value)
        return dns_names
    
    def encode_san_dns_names(self, san):
        """
        Return a list of x509.DNSName attributes from a list of strings.
        """
        dns_names = []
        for dns_name in san:
            dns_names.append(x509.DNSName(dns_name))
        return dns_names
    
    def encode_certificate(self, cert):
        """
        Return the PEM string encoded version of the certificate object.
        """
        return cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode(encoding="UTF-8")
    
    def encode_key(self, key):
        """
        Return the PEM encoded version of the provided private RSA key object
        """
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(encoding="UTF-8")
    
    def generate_csr(self, key, cn, san=None):
        """
        Using the provided rsa key object, a string common name, and a list of
        string subject alternative names, generate and return a csr object.
        """
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            self.generate_x509_name(cn)
        )
        if san:
            dns_names = self.encode_san_dns_names(san)
            csr = csr.add_extension(
                x509.SubjectAlternativeName(dns_names),
                critical=False,
            )
        return csr.sign(key, hashes.SHA256(), default_backend())
