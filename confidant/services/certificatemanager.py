import datetime
import hashlib
import logging
import time

from cryptography import x509
from cryptography.x509.extensions import ExtensionNotFound
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from lru import LRU

import confidant.clients
from confidant import settings
from confidant.utils import stats

logger = logging.getLogger(__name__)


class CachedCertificate(object):
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


class CertificateCache(object):
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
                'Attempting to release a non-existent lock in the certificate'
                ' cache.'
            )

    def set_response(self, cache_id, response):
        self.certificates[cache_id].response = response

    def get_cache_id(self, cn, validity, san):
        """
        Return a unique string from the provided arguments, for use in the
        certificate cache. The current day is included in the id, to ensure
        cache invalidation (minumum validity is 1 day).
        """
        date = datetime.datetime.today().strftime('%Y-%m-%d')
        return '{}{}{}{}'.format(cn, validity, san, date)


class CertificateCacheNoOp(object):
    def get(self, cache_id):
        return None

    def lock(self, cache_id):
        return None

    def release(self, cache_id):
        return None

    def set_response(self, cache_id, response):
        return None

    def get_cache_id(self, cn, validity, san):
        return ''


class CertificateAuthorityNotFoundError(Exception):
    pass


class CertificateNotReadyError(Exception):
    pass


class CertificateAuthority(object):
    def __init__(self, ca):
        try:
            self.ca_name = ca
            self.settings = settings.ACM_PRIVATE_CA_SETTINGS[ca]
        except KeyError:
            raise CertificateAuthorityNotFoundError()
        if self.settings['certificate_use_cache']:
            self.cache = CertificateCache(
                self.settings['certificate_cache_size'],
            )
        else:
            self.cache = CertificateCacheNoOp()

    def generate_key(self):
        """
        Generate and return a private RSA key object
        """
        key = rsa.generate_private_key(
            public_exponent=self.settings['key_public_exponent_size'],
            key_size=self.settings['key_size'],
            backend=default_backend()
        )
        return key

    def encode_key(self, key):
        """
        Return the PEM encoded version of the provided private RSA key object
        """
        return key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(encoding='UTF-8')

    def generate_x509_name(self, cn):
        """
        For the given common name string, generate and return an x509.Name, with
        attributes configured in the settings.
        """
        name_attributes = [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
        if self.settings['csr_country_name']:
            name_attributes.append(
                x509.NameAttribute(
                    NameOID.COUNTRY_NAME,
                    self.settings['csr_country_name'],
                )
            )
        if self.settings['csr_state_or_province_name']:
            name_attributes.append(
                x509.NameAttribute(
                    NameOID.STATE_OR_PROVINCE_NAME,
                    self.settings['csr_state_or_province_name'],
                )
            )
        if self.settings['csr_locality_name']:
            name_attributes.append(
                x509.NameAttribute(
                    NameOID.LOCALITY_NAME,
                    self.settings['csr_locality_name'],
                )
            )
        if self.settings['csr_organization_name']:
            name_attributes.append(
                x509.NameAttribute(
                    NameOID.ORGANIZATION_NAME,
                    self.settings['csr_organization_name'],
                )
            )
        return x509.Name(name_attributes)

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

    def encode_csr(self, csr):
        """
        Return a PEM string encoded version of the csr object.
        """
        return csr.public_bytes(
            serialization.Encoding.PEM,
        ).decode(encoding='UTF-8')

    def decode_csr(self, pem_csr):
        """
        Return a csr object from the pem encoded csr.
        """
        pem_csr = pem_csr.encode(encoding='UTF-8')
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
            san = csr.extensions.get_extension_for_class(
                x509.SubjectAlternativeName
            )
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

    def generate_self_signed_certificate(self, key, cn, validity, san=None):
        """
        Using the provided rsa key, a string common name, a validity (in number
        of days), and a list of subject alternative names (as strings), generate
        and return a signed certificate object.
        """
        _validity = min(validity, self.settings['max_validity_days'])
        subject = self.generate_x509_name(cn)
        issuer = subject
        # x509.CertificateBuilder functions return modified versions of the
        # object, so it's weirdly meant to be chained as function calls, making
        # this look weirdly javascript-like.
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
            dns_names = self.encode_san_dns_names(san)
            cert = cert.add_extension(
                x509.SubjectAlternativeName(dns_names),
                critical=False,
            )
        return cert.sign(key, hashes.SHA256(), default_backend())

    def encode_certificate(self, cert):
        """
        Return the PEM string encoded version of the certificate object.
        """
        return cert.public_bytes(
            serialization.Encoding.PEM,
        ).decode(encoding='UTF-8')

    def issue_certificate(self, csr, validity):
        """
        Given a PEM encoded csr, and a validity for the certificate (in number
        of days), issue a certificate from ACM Private CA, and return the ARN
        of the issued certificate.
        """
        csr = csr.encode(encoding='UTF-8')
        with stats.timer('issue_certificate'):
            client = confidant.clients.get_boto_client('acm-pca')
            response = client.issue_certificate(
                CertificateAuthorityArn=self.settings['arn'],
                Csr=csr,
                SigningAlgorithm=self.settings['signing_algorithm'],
                Validity={
                    'Value': min(validity, self.settings['max_validity_days']),
                    'Type': 'DAYS',
                },
                # Quick/easy idempotent token is just a hash of the csr itself.
                # The token must be 36 chars or less.
                IdempotencyToken=hashlib.sha256(csr).hexdigest()[:36],
            )
            return response['CertificateArn']

    def _get_cached_certificate_with_key(self, cache_id):
        """
        For the cache id, get the cached response, or, if another thread is in
        the process of issuing the same certificate, wait for the other thread
        to populate the cache.
        """
        with stats.timer('get_cached_certificate_with_key'):
            item = self.cache.get(cache_id)
            # We're the first thread attempting to get this certificate
            if not item:
                return {}
            # A certificate hasn't been issued yet, but since the cache id
            # exists, another thread has requested the certificate.
            if not item.response and item.lock:
                raise CertificateNotReadyError()
            # If the other thread failed to get the certificate, we need to
            # ensure that this thread attempts to fetch a certificate.
            return item.response

    def issue_certificate_with_key(self, cn, validity, san=None):
        """
        Given the string common name, the validity length of the certificate (in
        number of days), and a list of subject alternative names, return a dict
        with the PEM encoded certificate, certificate chain, and private RSA
        key.
        """
        with stats.timer('issue_certificate_with_key'):
            cache_id = self.cache.get_cache_id(cn, validity, san)
            cached_response = self._get_cached_certificate_with_key(cache_id)
            if cached_response:
                stats.incr('get_cached_certificate_with_key.hit')
                logger.debug('Used cached response for {}'.format(cache_id))
                return cached_response
            stats.incr('get_cached_certificate_with_key.miss')
            key = self.generate_key()
            encoded_key = self.encode_key(key)
            if self.settings['self_sign']:
                cert = self.encode_certificate(
                    self.generate_self_signed_certificate(
                        key,
                        cn,
                        validity,
                        san,
                    )
                )
                return {
                    'certificate': cert,
                    'certificate_chain': cert,
                    'key': encoded_key,
                }
            csr = self.generate_csr(key, cn, san)
            try:
                # set a lock
                self.cache.lock(cache_id)
                arn = self.issue_certificate(self.encode_csr(csr), validity)
                response = self.get_certificate_from_arn(arn)
                response['key'] = encoded_key
                self.cache.set_response(cache_id, response)
            finally:
                # release the lock
                self.cache.release(cache_id)
            return response

    def get_certificate_from_arn(self, certificate_arn):
        """
        Get the PEM encoded certificate from the provided ARN.
        """
        with stats.timer('get_certificate_from_arn'):
            client = confidant.clients.get_boto_client('acm-pca')
            # When a certificate is issued, it may take a while before it's
            # available via get_certificate. We need to keep retrying until it's
            # fully issued.
            i = 0
            while True:
                try:
                    response = client.get_certificate(
                        CertificateAuthorityArn=self.settings['arn'],
                        CertificateArn=certificate_arn,
                    )
                    break
                except client.exceptions.RequestInProgressException:
                    # Sleep for a maximum of 10 seconds
                    if i >= 50:
                        raise
                    logger.debug(
                        'Sleeping in get_certificate_from_arn for {}'.format(
                            certificate_arn,
                        )
                    )
                    time.sleep(.200)
                    i = i + 1
            return {
                'certificate': response['Certificate'],
                'certificate_chain': response['CertificateChain'],
            }

    def get_certificate_authority_certificate(self):
        """
        Return the PEM encoded CA certificate and certificate chain from the CA
        ARN.
        """
        client = confidant.clients.get_boto_client('acm-pca')
        certificate = client.get_certificate_authority_certificate(
            CertificateAuthorityArn=self.settings['arn'],
        )
        # TODO: support pagination for this call
        tags = client.list_tags(
            CertificateAuthorityArn=self.settings['arn'],
        )
        _tags = {}
        for tag in tags['Tags']:
            _tags[tag['Key']] = tag['Value']
        return {
            'ca': self.ca_name,
            'certificate': certificate['Certificate'],
            'certificate_chain': certificate['CertificateChain'],
            'tags': _tags,
        }


_CAS = {}


def get_ca(ca):
    if ca not in _CAS:
        _CAS[ca] = CertificateAuthority(ca)
    return _CAS[ca]


def list_cas():
    """
    Return detailed CA information for all CAs.
    """
    cas = []
    for ca in settings.ACM_PRIVATE_CA_SETTINGS:
        _ca = get_ca(ca)
        cas.append(_ca.get_certificate_authority_certificate())
    return cas
