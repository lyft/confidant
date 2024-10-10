import logging
from abc import ABC, abstractmethod
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import datetime
from lru import LRU

logger = logging.getLogger(__name__)


class CertificateAuthorityNotFoundError(Exception):
    pass


class CertificateNotReadyError(Exception):
    pass


class CachedCertificate:
    def __init__(self, lock=False, response=None):
        self._lock = lock
        self._response = response

    @property
    def lock(self):
        return self._lock

    @lock.setter
    def lock(self, value):
        self._lock = value

    @property
    def response(self):
        return self._response

    @response.setter
    def response(self, value):
        self._response = value


class CertificateCache:
    def __init__(self, cache_size):
        self.certificates = LRU(cache_size)

    def get(self, cache_id):
        """
        Get the CachedCertificate for the given cache_id.
        """
        return self.certificates.get(cache_id)

    def lock(self, cache_id):
        """
        Lock the CachedCertificate for the given cache_id. If the id is not in
        the cache, create a CachedCertificate for the cache_id, add it to the
        cache, and lock it.
        """
        if cache_id in self.certificates:
            self.certificates[cache_id].lock = True
        else:
            self.certificates[cache_id] = CachedCertificate(
                lock=True,
                response=None,
            )

    def release(self, cache_id):
        if cache_id in self.certificates:
            self.certificates[cache_id].lock = False
        else:
            logger.warning(
                "Attempting to release a non-existent lock in the certificate" " cache."
            )

    def set_response(self, cache_id, response):
        self.certificates[cache_id].response = response

    def get_cache_id(self, cn, validity, san):
        """
        Return a unique string from the provided arguments, for use in the
        certificate cache. The current day is included in the id, to ensure
        cache invalidation (minumum validity is 1 day).
        """
        date = datetime.datetime.today().strftime("%Y-%m-%d")
        return "{}{}{}{}".format(cn, validity, san, date)


class CertificateCacheNoOp:
    def get(self, cache_id):
        return None

    def lock(self, cache_id):
        return None

    def release(self, cache_id):
        return None

    def set_response(self, cache_id, response):
        return None

    def get_cache_id(self, cn, validity, san):
        return ""


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
