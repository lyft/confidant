from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.backends import default_backend


class CertificateAuthority:
    @abstractmethod
    def __init__(self, ca: str):
        pass

    @abstractmethod
    def issue_certificate(self, csr, validity):
        pass

    def decode_csr(self, pem_csr):
        """
        Return a csr object from the pem encoded csr.
        """
        pem_csr = pem_csr.encode(encoding="UTF-8")
        return x509.load_pem_x509_csr(pem_csr, default_backend())
