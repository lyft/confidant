import datetime

import pytest
from pytest_mock.plugin import MockerFixture
from cryptography.hazmat.primitives import hashes

from confidant.services.certificate_authority.acmpca import (
    ACMPrivateCertificateAuthority,
    CertificateCache,
)
from confidant.services.certificate_authority.certificateauthoritybase import (
    CertificateNotReadyError,
)


@pytest.fixture()
def ca_object(mocker: MockerFixture) -> ACMPrivateCertificateAuthority:
    ca_object = ACMPrivateCertificateAuthority("development")
    ca_object.settings["csr_country_name"] = "US"
    ca_object.settings["csr_state_or_province_name"] = "California"
    ca_object.settings["csr_locality_name"] = "San Francisco"
    ca_object.settings["csr_organization_name"] = "Example Inc."
    mocker.patch(
        "confidant.services.certificatemanager.get_ca", return_value=ca_object
    )
    return ca_object


def test_certificate_cache():
    cache = CertificateCache(5)
    cache_id = cache.get_cache_id("test.example.com", 7, [])
    cache.lock(cache_id)
    item = cache.get(cache_id)
    assert item.lock is True
    cache.set_response(cache_id, {"test": "me"})
    assert item.response
    cache.release(cache_id)
    assert item.lock is False
    # Cache size is 5, make sure if we stuff the cache, that the intial
    # item is gone.
    cache.lock(cache.get_cache_id("test1.example.com", 7, []))
    cache.lock(cache.get_cache_id("test2.example.com", 7, []))
    cache.lock(cache.get_cache_id("test3.example.com", 7, []))
    cache.lock(cache.get_cache_id("test4.example.com", 7, []))
    cache.lock(cache.get_cache_id("test5.example.com", 7, []))
    assert cache.get(cache_id) is None


def test_generate_key(ca_object: ACMPrivateCertificateAuthority):
    print(type(ca_object))
    ca_object.settings["key_size"] = 1024
    key = ca_object.generate_key()
    assert key.key_size == 1024


def test_encode_key(ca_object: ACMPrivateCertificateAuthority):
    key = ca_object.generate_key()
    encoded_key = ca_object.encode_key(key)
    assert encoded_key.startswith("-----BEGIN RSA PRIVATE KEY-----")


def test_generate_x509_name(ca_object: ACMPrivateCertificateAuthority):
    x509_name = ca_object.generate_x509_name("test.example.com")
    assert x509_name.rfc4514_string() == (
        "O=Example Inc.,L=San Francisco,ST=California,C=US,CN=test.example.com"
    )


def test_generate_csr(ca_object: ACMPrivateCertificateAuthority):
    key = ca_object.generate_key()
    san = ["test2.example.com", "test3.example.com"]
    csr = ca_object.generate_csr(key, "test.example.com", san)
    assert csr.is_signature_valid is True
    assert csr.subject.rfc4514_string() == (
        "O=Example Inc.,L=San Francisco,ST=California,C=US,CN=test.example.com"
    )


def test_encode_csr(ca_object: ACMPrivateCertificateAuthority):
    key = ca_object.generate_key()
    csr = ca_object.generate_csr(key, "test.example.com")
    encoded_csr = ca_object.encode_csr(csr)
    assert encoded_csr.startswith("-----BEGIN CERTIFICATE REQUEST-----")


def test_decode_csr(ca_object: ACMPrivateCertificateAuthority):
    encoded_csr = "-----BEGIN CERTIFICATE REQUEST-----\nMIICwDCCAagCAQAwajEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTELMAkGA1UE\nBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lz\nY28xEzARBgNVBAoMCkx5ZnQsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDqAFNwMlG3DiPJzUgSfzInRlAYdZzycz/mRsw5Boucii4jBQpLfhp/\nwjkbClAuuwLIija5yv95zChxbJPJ6Je1FtcXtbXAEVjWnf+B1s/OEA+uSO8IoGiL\nsYRNFqXI2hyzcqMshnxc90+qfMB+/eAv17t0fkMjT028N5I/Rvqh0RQx9l+0AbvH\nPtNBzNSWj9s/Oy4mEaXary/S3VZPd+38hpXc3HQINczmSKQTG/pPKwQcg+dQMjQz\nvlPuntrgvy5S2mK5D0xOCfLUfNVT7qb89/Rd9siZw7VMzL/XDkNtVZEEuJAL16PN\n/1zPQO6jxqNes0PqeWz0brsrx6LqhxiPAgMBAAGgETAPBgkqhkiG9w0BCQ4xAjAA\nMA0GCSqGSIb3DQEBCwUAA4IBAQBZaU01DoLf4Ldum/gOrjc+R1lqgXna6Thu/DHs\nAKbPyztjQjRwGApoPUXqRs6MYpB8XJOal4rsYazybxRNsiIQV/yNtlToVsz86lys\nPP85zzk7nZTT28gMew/iuS7H0in4XJz3LWdDxVIk+P4ktiqTOQSQyqMBGM+Rw93Y\nBDCfk1/pigxis0umyfp6Ho/qfdKEr4MYi2UZfTIl8F8dLq+PKPzqK+sEEOBDOUtP\nc4Edeg3PL1XROiwv3uPhtfaIe1iVD4IjWxNN06anoa29xMmJ/vXkaqYLQSd+FKHe\ny00DRxiYx7zqqfByUAUV3pPRwytFMit5bsOEAlhYmTRc2PEx\n-----END CERTIFICATE REQUEST-----\n"  # noqa:E501
    csr = ca_object.decode_csr(encoded_csr)
    assert csr.is_signature_valid is True


def test_get_csr_common_name(ca_object: ACMPrivateCertificateAuthority):
    key = ca_object.generate_key()
    csr = ca_object.generate_csr(key, "test.example.com")
    assert ca_object.get_csr_common_name(csr) == "test.example.com"


def test_get_csr_san(ca_object: ACMPrivateCertificateAuthority):
    key = ca_object.generate_key()
    san = ["test1.example.com", "test2.example.com"]
    csr = ca_object.generate_csr(key, "test.example.com", san)
    assert ca_object.get_csr_san(csr) == san


def test_encode_san_dns_names(ca_object: ACMPrivateCertificateAuthority):
    san = ["test1.example.com", "test2.example.com"]
    dns_names = ca_object.encode_san_dns_names(san)
    assert len(dns_names) == len(san)
    for dns_name in dns_names:
        assert dns_name.value in san


def test_generate_self_signed_certificate(
    ca_object: ACMPrivateCertificateAuthority,
):
    key = ca_object.generate_key()
    san = ["test1.example.com", "test2.example.com"]
    cert = ca_object.generate_self_signed_certificate(
        key,
        "test.example.com",
        7,
        san,
    )
    delta = datetime.timedelta(days=7)
    assert cert.not_valid_after - cert.not_valid_before == delta
    assert cert.subject.rfc4514_string() == (
        "O=Example Inc.,L=San Francisco,ST=California,C=US,CN=test.example.com"
    )
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)


def test_encode_certificate(ca_object: ACMPrivateCertificateAuthority):
    key = ca_object.generate_key()
    cert = ca_object.generate_self_signed_certificate(
        key,
        "test.example.com",
        7,
    )
    encoded_cert = ca_object.encode_certificate(cert)
    assert encoded_cert.startswith("-----BEGIN CERTIFICATE-----")


def test_issue_certificate(
    mocker: MockerFixture, ca_object: ACMPrivateCertificateAuthority
):
    client_mock = mocker.patch(
        "confidant.clients.get_boto_client",
        autospec=True,
    )
    issue_certificate_mock = mocker.MagicMock()
    issue_certificate_mock.issue_certificate.return_value = {
        "CertificateArn": "test",
    }
    client_mock.return_value = issue_certificate_mock
    key = ca_object.generate_key()
    csr = ca_object.generate_csr(key, "test.example.com", [])
    encoded_csr = ca_object.encode_csr(csr)
    mocker.patch(
        "confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority._get_certificate_from_arn",  # noqa:E501
        return_value={
            "certificate": "test_certificate",
            "certificate_chain": "test_certificate_chain",
        },
    )
    response = ca_object.issue_certificate(encoded_csr, 7)
    assert response == {
        "certificate": "test_certificate",
        "certificate_chain": "test_certificate_chain",
    }


def test__get_cached_certificate_with_key(
    mocker: MockerFixture, ca_object: ACMPrivateCertificateAuthority
):
    ca_object.settings["certificate_use_cache"] = False
    assert ca_object._get_cached_certificate_with_key("test") == {}
    ca_object.settings["certificate_use_cache"] = True
    cache = CertificateCache(10)
    ca_object.cache = cache
    assert ca_object._get_cached_certificate_with_key("test") == {}
    cache.lock("test")
    cache.set_response("test", {"hello": "world"})
    assert ca_object._get_cached_certificate_with_key("test") == {
        "hello": "world"
    }  # noqa:E501
    # test lock loop
    cache.lock("test1")
    item = mocker.MagicMock()
    type(item).lock = mocker.PropertyMock(side_effect=[True, False])
    type(item).response = mocker.PropertyMock(
        side_effect=[None, {"hello": "world"}]
    )
    mocker.patch(
        "confidant.services.certificate_authority.acmpca.CertificateCache.get",
        return_value=item,
    )
    with pytest.raises(CertificateNotReadyError):
        ca_object._get_cached_certificate_with_key("test1")


def test_issue_certificate_with_key(
    mocker: MockerFixture, ca_object: ACMPrivateCertificateAuthority
):
    ca_object.settings["self_sign"] = True
    data = ca_object.issue_certificate_with_key("test.example.com", 7)
    assert data["certificate"].startswith("-----BEGIN CERTIFICATE-----")
    assert data["certificate_chain"].startswith("-----BEGIN CERTIFICATE-----")
    assert data["key"].startswith("-----BEGIN RSA PRIVATE KEY-----")

    mocker.patch(
        "confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority._get_cached_certificate_with_key",  # noqa:E501
        return_value={"hello": "world"},
    )
    data = ca_object.issue_certificate_with_key("test.example.com", 7)
    assert data == {"hello": "world"}
    mocker.patch(
        "confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority._get_cached_certificate_with_key",  # noqa:E501
        return_value={},
    )

    ca_object.settings["self_sign"] = False
    mocker.patch(
        "confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority.issue_certificate",  # noqa:E501
        return_value="test-certificate-arn",
    )
    mocker.patch(
        "confidant.services.certificate_authority.acmpca.ACMPrivateCertificateAuthority._get_certificate_from_arn",  # noqa:E501
        return_value={
            "certificate": "test_certificate",
            "certificate_chain": "test_certificate_chain",
        },
    )
    data = ca_object.issue_certificate_with_key("test.example.com", 7)
    assert data["certificate"] == "test_certificate"
    assert data["certificate_chain"] == "test_certificate_chain"
    assert data["key"].startswith("-----BEGIN RSA PRIVATE KEY-----")


def test_get_certificate_from_arn_no_exception(
    mocker: MockerFixture, ca_object: ACMPrivateCertificateAuthority
):
    time_mock = mocker.patch("time.sleep")
    client_mock = mocker.patch(
        "confidant.clients.get_boto_client",
        autospec=True,
    )
    get_certificate_mock = mocker.MagicMock()
    get_certificate_mock.get_certificate.return_value = {
        "Certificate": "test",
        "CertificateChain": "test_chain",
    }
    client_mock.return_value = get_certificate_mock
    data = ca_object._get_certificate_from_arn("test_arn")
    assert time_mock.called is False
    assert data == {"certificate": "test", "certificate_chain": "test_chain"}


def test_get_certificate_from_arn_with_exception(
    mocker: MockerFixture, ca_object: ACMPrivateCertificateAuthority
):
    class RequestInProgressException(Exception):
        pass

    time_mock = mocker.patch("time.sleep")
    client_mock = mocker.patch(
        "confidant.clients.get_boto_client",
        autospec=True,
    )
    get_certificate_mock = mocker.MagicMock()
    get_certificate_mock.exceptions.RequestInProgressException = (
        RequestInProgressException  # noqa:E501
    )
    get_certificate_mock.get_certificate.side_effect = [
        RequestInProgressException(),
        {"Certificate": "test", "CertificateChain": "test_chain"},
    ]
    client_mock.return_value = get_certificate_mock
    data = ca_object._get_certificate_from_arn("test_arn")
    assert time_mock.called is True
    assert data == {"certificate": "test", "certificate_chain": "test_chain"}


def test_get_certificate_authority_certificate(
    mocker: MockerFixture, ca_object: ACMPrivateCertificateAuthority
):
    client_mock = mocker.patch(
        "confidant.clients.get_boto_client",
        autospec=True,
    )
    gcac_mock = mocker.MagicMock()
    gcac_mock.get_certificate_authority_certificate.return_value = {
        "Certificate": "test-certificate",
        "CertificateChain": "test-certificate-chain",
    }
    gcac_mock.list_tags.return_value = {
        "Tags": [
            {"Key": "environment", "Value": "development"},
            {"Key": "extra", "Value": "extra-value"},
        ],
    }
    client_mock.return_value = gcac_mock
    data = ca_object.get_certificate_authority_certificate()
    assert data == {
        "ca": "development",
        "certificate": "test-certificate",
        "certificate_chain": "test-certificate-chain",
        "tags": {
            "environment": "development",
            "extra": "extra-value",
        },
    }
