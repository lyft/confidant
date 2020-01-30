import datetime

from cryptography.hazmat.primitives import hashes

from confidant.services import certificatemanager


def test_generate_key(mocker):
    mocker.patch('confidant.settings.ACM_PRIVATE_CA_KEY_SIZE', 1024)
    key = certificatemanager.generate_key()
    assert key.key_size == 1024


def test_encode_key():
    key = certificatemanager.generate_key()
    encoded_key = certificatemanager.encode_key(key)
    assert encoded_key.startswith(b'-----BEGIN RSA PRIVATE KEY-----')


def test_generate_x509_name(mocker):
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME',
        'US',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME',
        'California',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_LOCALITY_NAME',
        'San Francisco',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_ORGANIZATION_NAME',
        'Example Inc.',
    )
    x509_name = certificatemanager.generate_x509_name('test.example.com')
    assert x509_name.rfc4514_string() == (
        'CN=test.example.com,C=US,ST=California,L=San Francisco,O=Example Inc.'
    )


def test_generate_csr(mocker):
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME',
        'US',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME',
        'California',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_LOCALITY_NAME',
        'San Francisco',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_ORGANIZATION_NAME',
        'Example Inc.',
    )
    key = certificatemanager.generate_key()
    san = ['test2.example.com', 'test3.example.com']
    csr = certificatemanager.generate_csr(key, 'test.example.com', san)
    assert csr.is_signature_valid is True
    assert csr.subject.rfc4514_string() == (
        'CN=test.example.com,C=US,ST=California,L=San Francisco,O=Example Inc.'
    )


def test_encode_csr():
    key = certificatemanager.generate_key()
    csr = certificatemanager.generate_csr(key, 'test.example.com')
    encoded_csr = certificatemanager.encode_csr(csr)
    assert encoded_csr.startswith(b'-----BEGIN CERTIFICATE REQUEST-----')


def test_decode_csr():
    encoded_csr = b'-----BEGIN CERTIFICATE REQUEST-----\nMIICwDCCAagCAQAwajEZMBcGA1UEAwwQdGVzdC5leGFtcGxlLmNvbTELMAkGA1UE\nBhMCVVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lz\nY28xEzARBgNVBAoMCkx5ZnQsIEluYy4wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw\nggEKAoIBAQDqAFNwMlG3DiPJzUgSfzInRlAYdZzycz/mRsw5Boucii4jBQpLfhp/\nwjkbClAuuwLIija5yv95zChxbJPJ6Je1FtcXtbXAEVjWnf+B1s/OEA+uSO8IoGiL\nsYRNFqXI2hyzcqMshnxc90+qfMB+/eAv17t0fkMjT028N5I/Rvqh0RQx9l+0AbvH\nPtNBzNSWj9s/Oy4mEaXary/S3VZPd+38hpXc3HQINczmSKQTG/pPKwQcg+dQMjQz\nvlPuntrgvy5S2mK5D0xOCfLUfNVT7qb89/Rd9siZw7VMzL/XDkNtVZEEuJAL16PN\n/1zPQO6jxqNes0PqeWz0brsrx6LqhxiPAgMBAAGgETAPBgkqhkiG9w0BCQ4xAjAA\nMA0GCSqGSIb3DQEBCwUAA4IBAQBZaU01DoLf4Ldum/gOrjc+R1lqgXna6Thu/DHs\nAKbPyztjQjRwGApoPUXqRs6MYpB8XJOal4rsYazybxRNsiIQV/yNtlToVsz86lys\nPP85zzk7nZTT28gMew/iuS7H0in4XJz3LWdDxVIk+P4ktiqTOQSQyqMBGM+Rw93Y\nBDCfk1/pigxis0umyfp6Ho/qfdKEr4MYi2UZfTIl8F8dLq+PKPzqK+sEEOBDOUtP\nc4Edeg3PL1XROiwv3uPhtfaIe1iVD4IjWxNN06anoa29xMmJ/vXkaqYLQSd+FKHe\ny00DRxiYx7zqqfByUAUV3pPRwytFMit5bsOEAlhYmTRc2PEx\n-----END CERTIFICATE REQUEST-----\n'  # noqa:E501
    csr = certificatemanager.decode_csr(encoded_csr)
    assert csr.is_signature_valid is True


def test_get_csr_common_name():
    key = certificatemanager.generate_key()
    csr = certificatemanager.generate_csr(key, 'test.example.com')
    assert certificatemanager.get_csr_common_name(csr) == 'test.example.com'


def test_get_csr_san():
    key = certificatemanager.generate_key()
    san = ['test1.example.com', 'test2.example.com']
    csr = certificatemanager.generate_csr(key, 'test.example.com', san)
    assert certificatemanager.get_csr_san(csr) == san


def test_encode_san_dns_names():
    san = ['test1.example.com', 'test2.example.com']
    dns_names = certificatemanager.encode_san_dns_names(san)
    assert len(dns_names) == len(san)
    for dns_name in dns_names:
        assert dns_name.value in san


def test_generate_self_signed_certificate(mocker):
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_COUNTRY_NAME',
        'US',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_STATE_OR_PROVINCE_NAME',
        'California',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_LOCALITY_NAME',
        'San Francisco',
    )
    mocker.patch(
        'confidant.settings.ACM_PRIVATE_CA_CSR_ORGANIZATION_NAME',
        'Example Inc.',
    )
    key = certificatemanager.generate_key()
    san = ['test1.example.com', 'test2.example.com']
    cert = certificatemanager.generate_self_signed_certificate(
        key,
        'test.example.com',
        7,
        san,
    )
    delta = datetime.timedelta(days=7)
    assert cert.not_valid_after - cert.not_valid_before == delta
    assert cert.subject.rfc4514_string() == (
        'CN=test.example.com,C=US,ST=California,L=San Francisco,O=Example Inc.'
    )
    assert isinstance(cert.signature_hash_algorithm, hashes.SHA256)


def test_encode_certificate():
    key = certificatemanager.generate_key()
    cert = certificatemanager.generate_self_signed_certificate(
        key,
        'test.example.com',
        7,
    )
    encoded_cert = certificatemanager.encode_certificate(cert)
    assert encoded_cert.startswith(b'-----BEGIN CERTIFICATE-----')


def test_issue_certificate(mocker):
    client_mock = mocker.patch(
        'confidant.clients.get_boto_client',
        autospec=True,
    )
    issue_certificate_mock = mocker.MagicMock()
    issue_certificate_mock.issue_certificate.return_value = {
        'CertificateArn': 'test',
    }
    client_mock.return_value = issue_certificate_mock
    key = certificatemanager.generate_key()
    csr = certificatemanager.generate_csr(key, 'test.example.com', [])
    encoded_csr = certificatemanager.encode_csr(csr)
    assert certificatemanager.issue_certificate(encoded_csr, 7) == 'test'


def test_issue_and_get_certificate(mocker):
    mocker.patch(
        'confidant.services.certificatemanager.get_certificate_from_arn',
        return_value={
            'Certificate': 'test_certificate',
            'CertificateChain': 'test_certificate_chain',
        },
    )
    mocker.patch('confidant.services.certificatemanager.issue_certificate')
    key = certificatemanager.generate_key()
    csr = certificatemanager.generate_csr(key, 'test.example.com', [])
    data = certificatemanager.issue_and_get_certificate(csr, 7)
    assert data['certificate'] == 'test_certificate'
    assert data['certificate_chain'] == 'test_certificate_chain'


def test_issue_certificate_with_key(mocker):
    mocker.patch('confidant.settings.ACM_PRIVATE_CA_SELF_SIGN', True)
    data = certificatemanager.issue_certificate_with_key('test.example.com', 7)
    assert data['certificate'].startswith(b'-----BEGIN CERTIFICATE-----')
    assert data['certificate_chain'].startswith(b'-----BEGIN CERTIFICATE-----')
    assert data['key'].startswith(b'-----BEGIN RSA PRIVATE KEY-----')

    mocker.patch('confidant.settings.ACM_PRIVATE_CA_SELF_SIGN', False)
    mocker.patch(
        'confidant.services.certificatemanager.issue_and_get_certificate',
        return_value={
            'certificate': 'test_certificate',
            'certificate_chain': 'test_certificate_chain',
        },
    )
    data = certificatemanager.issue_certificate_with_key('test.example.com', 7)
    assert data['certificate'] == 'test_certificate'
    assert data['certificate_chain'] == 'test_certificate_chain'
    assert data['key'].startswith(b'-----BEGIN RSA PRIVATE KEY-----')


def test_get_certificate_from_arn_no_exception(mocker):
    time_mock = mocker.patch('time.sleep')
    client_mock = mocker.patch(
        'confidant.clients.get_boto_client',
        autospec=True,
    )
    get_certificate_mock = mocker.MagicMock()
    get_certificate_mock.get_certificate.return_value = 'test'
    client_mock.return_value = get_certificate_mock
    data = certificatemanager.get_certificate_from_arn('test_arn')
    assert time_mock.called is False
    assert data == 'test'


def test_get_certificate_from_arn_with_exception(mocker):
    class RequestInProgressException(Exception):
        pass

    time_mock = mocker.patch('time.sleep')
    client_mock = mocker.patch(
        'confidant.clients.get_boto_client',
        autospec=True,
    )
    get_certificate_mock = mocker.MagicMock()
    get_certificate_mock.exceptions.RequestInProgressException = RequestInProgressException  # noqa:E501
    get_certificate_mock.get_certificate.side_effect = [
        RequestInProgressException(),
        'test',
    ]
    client_mock.return_value = get_certificate_mock
    data = certificatemanager.get_certificate_from_arn('test_arn')
    assert time_mock.called is True
    assert data == 'test'


def test_get_certificate_authority_certificate(mocker):
    client_mock = mocker.patch(
        'confidant.clients.get_boto_client',
        autospec=True,
    )
    gcac_mock = mocker.MagicMock()
    gcac_mock.get_certificate_authority_certificate.return_value = 'test'
    client_mock.return_value = gcac_mock
    data = certificatemanager.get_certificate_authority_certificate()
    assert data == 'test'
