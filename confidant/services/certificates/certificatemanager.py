import logging
from enum import Enum

from confidant.services.certificates.acm_private_certificate_authority import (
    ACMPrivateCertificateAuthority,
)
from confidant.services.certificates.custom_certificate_authority import (
    CustomCertificateAuthority,
)

from confidant import settings

logger = logging.getLogger(__name__)


class CAType(Enum):
    """Enum for CA types."""
    AWS_ACM_PCA = "aws_acm_pca"
    CUSTOM_CA = "custom_ca"


_CAS = {}


def get_ca(ca):
    """get_ca returns a CertificateAuthority object for the given CA,
    based on the CA type in settings.
    """
    if ca not in _CAS:
        if settings.CA_TYPE == "aws_acm_pca":
            _CAS[ca] = ACMPrivateCertificateAuthority(ca)
        elif settings.CA_TYPE == "custom_ca":
            _CAS[ca] = CustomCertificateAuthority(ca)
        else:
            raise ValueError(f"Unknown CA type: {settings.CA_TYPE}")
    return _CAS[ca]


def list_cas():
    """
    Return detailed CA information for all CAs.
    """
    cas = []
    if settings.CA_TYPE == "aws_acm_pca":
        for ca in settings.ACM_PRIVATE_CA_SETTINGS:
            _ca = get_ca(ca)
            cas.append(_ca.get_certificate_authority_certificate())
    elif settings.CA_TYPE == "custom_ca":
        for ca in settings.CUSTOM_CERTIFICATE_AUTHORITIES:
            _ca = get_ca(ca)
            cas.append(_ca.get_certificate_authority_certificate())
    else:
        raise ValueError(f"Unknown CA type: {settings.CA_TYPE}")
    return cas
