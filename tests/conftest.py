import pytest

from jwcrypto import jwk


@pytest.fixture(autouse=True)
def encrypted_settings_mock(mocker):
    mocker.patch('confidant.settings.encrypted_settings.secret_string', {})
    mocker.patch(
        'confidant.settings.encrypted_settings.decrypted_secrets',
        {'SESSION_SECRET': 'TEST_KEY'},
    )


@pytest.fixture
def test_key_pair():
    test_private_key = \
        b'-----BEGIN PRIVATE KEY-----\n' \
        b'MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDUu1TaFSVNJELf\n' \
        b'YiV++1ZDAbrQ/flor64XOwK9RItzYqvnEUU1+aHw4QvDNyKJsyH7/uqv42vDZiCi\n' \
        b'AH6T1RVLD30AdIswOQpVSsQcPEXcJfkIJ3ZQSWpuTVMbvJukrWK9ScPFkUyBC7Fp\n' \
        b'kZ/RJ6pwiE2nVHjcrysAmK2/KB1Hk/NmO+fwevIcYXwrxNLm9k6XM5xyJcl7ZK3G\n' \
        b'InZbuEcH4NdRYnAo7dCLtuwRFUW4fgSRUjjxFXGJLd830iDgHzM0VyTq77gzKpn5\n' \
        b'VEZbIvDWgc8oxKHsrJKbyv3UGeC0q04K2EQR6tq71gbS/hv9QCxmR6ygNqq8bz0d\n' \
        b'smZXeeYxAgMBAAECggEActo9Io0eGXsFW8OKiPc7iGvLqAAnAt0uub4TaYozW/We\n' \
        b'598MJesEAqAOELSYwg1jwMDNhm7bhKCD59Mqg7gciezvySoi58M0D/6QyMnF0ejy\n' \
        b'ffOITiqE+s5mm2gGBC/USmwj9WvQCS/99gg4Z9zpiV4dxsS1iDhOmEDWNYl73WNH\n' \
        b'4aXL6fxG59r943qpm3JJqqqW/wsFQELLrKDrSWCv6u4niJ/zBE/XS6GaeZRm5ZNI\n' \
        b'BxSRwuYQgNzFdi/cGLV3BPiwusT37pANvzCI+1ZUazKFVjTHPPdvFvpoFap24Foo\n' \
        b'IkVdpe4Fm6qbi66uCUXlXPyGbmA1lkmmskACE4/7kQKBgQD75RxndWb90YvJAjhL\n' \
        b'nDiXu8xe4p0wsDoFNGDuLag1ZKhkHfN3YG7PwZY+1aXUP0fgpGM9ivjWgctosmcR\n' \
        b'nHPnyUi846PWNV5KQPFzR1Fmg8xAr0LdeyZHZetQYB+21QvMdfFsU1qU0rhU07Og\n' \
        b'4CGVIJBZCpbMxSN4MCy57jFdvQKBgQDYMtWP7A2HwA0zxwn0rciF0VoTM6XERkz5\n' \
        b'nwrnYneFiiShMjUOrLxq5XSU3sawIw/MD0gRsbDkv3kMdGf32sjsopLKFSk8aXid\n' \
        b'BpLoaE7TRzSwJhmFSGNa4s3HBXqEjXJIgDDz3XlvZ/8h9WCQg/tJQ6IaV0oSx1q5\n' \
        b'bpO258CvhQKBgE6gqKoeuoRWKYUYHUx0ujGa3GNt51UwXRwMyojuVYg9IFcIBlxo\n' \
        b'DI7rRaPdesLy8dPMXHH0dFI49655qbSUmpVqfjr/779Ir2MMPJIYW+9dCp/SVVPf\n' \
        b'QgadaMORDbU7cVBkLHT829SCpilMX9DCxZjQLl6s8H+Atd6pYvyyvlQdAoGAVGo8\n' \
        b'0s4zVj7ZqM7dh0jXk9BzYC35WpKseYbs5f2fd2fB96K37rvpcb+X7oyxfZKjF2Uc\n' \
        b'GbSMwjQ02nUVJ0So0SSFNhxfFnSEIKOxdsdLh9k0rFaj/lOOX61Q9ZWhCeKEreRH\n' \
        b'uOBQCvzLNIIvqx2tXyTmRWyxwnVOajrPuEnzBVUCgYAKBdA3UC+Cu4f5nhn8FmG3\n' \
        b'YuTBwFrUB82BHCQxC7L3prsxWVuguZptWln0ng+yTQme+shre03BaONl7A95hfz5\n' \
        b'rhXTb8j86oFR6JIYf2Vfe6hrUBCxAxb4A1uDkt/GZMupHp+XiKCY8L+nKPjbX8aC\n' \
        b'PmsiJweOFGfkN7QBzsdhsg==\n' \
        b'-----END PRIVATE KEY-----\n'
    test_pair = jwk.JWK()
    test_pair.import_from_pem(test_private_key)
    return test_pair


@pytest.fixture
def test_jwk_payload():
    return {'test': 'something'}


@pytest.fixture
def test_jwt():
    return 'eyJhbGciOiJSUzI1NiIsImtpZCI6IjBoN1I4ZEwwclUtYjNwM29uZnRfQlBmdVJXMUxkN1lqc0ZuT1dKdUZYVUUiLCJ0eXAiOiJKV1Qi' \
           'fQ.eyJ0ZXN0Ijoic29tZXRoaW5nIn0.Xf0-IWayqR80a0MgquV6nYmm6QK5o71tgE9w0xgDm1Vdv0pOrZph4dGFw_2mTpTy8qUmQnCUU' \
           'ropc058TutRPyKJyIhNIt0oQzoiRVaMW5UXpOMs4d45SKkwVteI8vRSQqjlG0g0uTuZl1mc6rrBVdCMr03_v7HZ55fJyDgW-nOKo8XmU' \
           'BQsyvt9duNsVib-s0dv4JAGMvHVSoezUEmvEfcTForRby6m_SN96l9I14WhusHIAUweEbaPTtfr-7WAS9_hOdUMdD099UUANznjDErfP' \
           'p16uMm72oErcrubC9Xq4zMs7kdwYZ-57HS6A68FYLiIEBtZn1v5_2JYbwMLYA'


@pytest.fixture
def test_certificate():
    return b'-----BEGIN CERTIFICATE-----\n' \
            b'MIIDoDCCAogCCQDqKOyH38qgKDANBgkqhkiG9w0BAQsFADCBkTELMAkGA1UEBhMC\n' \
            b'VVMxCzAJBgNVBAgMAkNBMRYwFAYDVQQHDA1UZXN0IExvY2FsaXR5MRIwEAYDVQQK\n' \
            b'DAlMeWZ0IFRlc3QxEjAQBgNVBAsMCVRlc3QgVW5pdDENMAsGA1UEAwwEdGVzdDEm\n' \
            b'MCQGCSqGSIb3DQEJARYXdGVzdC1zb21ldGhpbmdAbHlmdC5jb20wHhcNMjIxMDA3\n' \
            b'MjMxNTM5WhcNMjMxMDA3MjMxNTM5WjCBkTELMAkGA1UEBhMCVVMxCzAJBgNVBAgM\n' \
            b'AkNBMRYwFAYDVQQHDA1UZXN0IExvY2FsaXR5MRIwEAYDVQQKDAlMeWZ0IFRlc3Qx\n' \
            b'EjAQBgNVBAsMCVRlc3QgVW5pdDENMAsGA1UEAwwEdGVzdDEmMCQGCSqGSIb3DQEJ\n' \
            b'ARYXdGVzdC1zb21ldGhpbmdAbHlmdC5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IB\n' \
            b'DwAwggEKAoIBAQDUu1TaFSVNJELfYiV++1ZDAbrQ/flor64XOwK9RItzYqvnEUU1\n' \
            b'+aHw4QvDNyKJsyH7/uqv42vDZiCiAH6T1RVLD30AdIswOQpVSsQcPEXcJfkIJ3ZQ\n' \
            b'SWpuTVMbvJukrWK9ScPFkUyBC7FpkZ/RJ6pwiE2nVHjcrysAmK2/KB1Hk/NmO+fw\n' \
            b'evIcYXwrxNLm9k6XM5xyJcl7ZK3GInZbuEcH4NdRYnAo7dCLtuwRFUW4fgSRUjjx\n' \
            b'FXGJLd830iDgHzM0VyTq77gzKpn5VEZbIvDWgc8oxKHsrJKbyv3UGeC0q04K2EQR\n' \
            b'6tq71gbS/hv9QCxmR6ygNqq8bz0dsmZXeeYxAgMBAAEwDQYJKoZIhvcNAQELBQAD\n' \
            b'ggEBAIPQnGGAlwbK+f4V7SUUjXnsO7oVlMtTO7JWAk+g8W9colUeMDHW/Ygcwu3e\n' \
            b'OlX5NSEV1wcQxuqyNWbEgrsZourePdVWujc/9qSVfaU/BjOj2CLylAf6ZNj/XpL/\n' \
            b'PNCSCLM40cbhw/SeiNZ9WxkuuHiC32QxmR4kyvvXcHEGqVA2cOVAvncstW4gGowi\n' \
            b'ObNYddXOmoOf8d5oHcO5vlhYyfbmShuq1PLygzUhG2jS+5aX9gmDtv+LtVGdXXWV\n' \
            b'zSCh3+H4NSUWs3P1pKDFIUT3jGLQ3UavIS5KCizfBUbltx6LBSgmBbHf89RsKBbT\n' \
            b'rxaukysD4sNgVHKptTq0fJ+2CjM=\n' \
            b'-----END CERTIFICATE-----\n'
