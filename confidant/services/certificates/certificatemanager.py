import logging
from enum import Enum

from confidant.services.certificates.acm_pca import ACMPrivateCertificateAuthority
from confidant.services.certificates.customca import CustomCertificateAuthority

from confidant import settings

logger = logging.getLogger(__name__)


class CAType(Enum):
    AWS_ACM_PCA = "aws_acm_pca"
    CUSTOM_CA = "custom_ca"


_CAS = {}


def get_ca(ca):
    if ca not in _CAS:
        print(settings.CA_TYPE)
        if settings.CA_TYPE == "aws_acm_pca":
            _CAS[ca] = ACMPrivateCertificateAuthority(ca)
        elif settings.CA_TYPE == "custom_ca":
            _CAS[ca] = CustomCertificateAuthority(ca)
        else:
            raise Exception(f"Unknown CA type: {settings.CA_TYPE}")
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
