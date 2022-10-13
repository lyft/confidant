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
def test_encrypted_key():
    return '-----BEGIN RSA PRIVATE KEY-----\n' \
        'Proc-Type: 4,ENCRYPTED\n' \
        'DEK-Info: AES-256-CBC,685402D4E755777F605320365C4D5036\n' \
        '\n' \
        '63er0s88QhGVf0qip7xtX8T9qPY0QzU1QP7o+lnv5rlCFFwQuIMMR7DdBRh0a4HH\n' \
        'H7P0jsxWZO4Cof565CDlu6Gyv0g4myvFwm0BSI1O6Lyo0ZYdnK7ZLDtymj5TxT9A\n' \
        'KtL498Ptg78RdMLgMaT5qyqS+aMfVYmQnpvHHKQOvfvVdQC+AomcXHvFCmq3j7/g\n' \
        'vqGHwFEqqzhf76VikKbTKz0KnrIpceG0FdK4N6IXksrKg5jytRyKMQwkvsH3f3uG\n' \
        'S/7C7FjLJyojv+1umhDyHlAi60uGQyME52hC0auBStXOeWHcGPgTMBu39BQ2QttY\n' \
        '8WZylkxxHfe0DF+MeatT83fh9c6aFMQZXcJVSVnTJfvpyTDM3VQfXdso78fsv7iU\n' \
        '7Toyrcr/8817hLDp51Wn0ZkiiacQcxm6rVUr+lXUMfCZHWVLtcs2Kkx68egCBnE5\n' \
        '2LqIQU86YgVurXLxtdAcRBvMLC2nO8P7y4RM202xpgB7nnnfIqa1p0ACIpCWo+Ti\n' \
        'WJp0Sm9Gk7Y4m5GX+Bk8XiW1EDk1VZKp0iXdl6if0kR30cmdr1wHevbyLDSzsK+E\n' \
        'qiQKtV47XFBiUIVhfWO+eOCPcpmWwbVD8pBze5P4Swldzd8HLVQ2jLAWINRQVQQI\n' \
        'tqUgfph0dNf4Zyk/DchoCmHv/0z7/SkgW4PFJhiviPCKVIejCH5gKDNjVfrvMczZ\n' \
        'G0OaBSW+uQoWKp/XTZl0SuBOK551oTbCJwsnb4ZTXv1bG73M0sJffxwh/rEdoJ3o\n' \
        'iwhzdh6JUFeak4gcD3C4qOwRyQhSiKYlLbiP38+dAJhb5jtXRc5TYZOAEnY9LzXs\n' \
        'gBK4IlzWUSdOf3ppSQP2Ff5WeGE10NbUuoSOBkfIQB0H3hi2EO8TnPcYgjZkMHMf\n' \
        'pljthTyuPepXPh16EdqV4qtFbO/XYroQ2WPYPyJyxA9sbNsFfTBn35oJBTBzk6Yk\n' \
        'Hnq4ENCiPJKbuF02HBu7vNitf9/dhhYLjAupXco5jWz9H9ZL5QQGY2oWDucJxBTs\n' \
        'rd31FZ1DCJwvHb9a9aTMNoZFv2AbqfmvJs9r/8S1cb3L7bgJmKqbjgFmWPTG8McJ\n' \
        'zthX44V/TOVWAKC5O//TPBD7jTHuboFwEuZ0k16HFX14Ko4SPVrmK6noWfGUM9RB\n' \
        'hDoEv40k1Vz8NW1n1/1rBKHM7mtYKW8lkcY+qrdlT5LStIPS7jhiTbYjFKyT1Jvv\n' \
        'sQE+S+Pbp5zTtrF9njFnhbFPxYn+3td3Uggl/IDC2prfkDc2ztwKgBlgR4jIxgHv\n' \
        'pi2i32qFwwImSr0/D7z+sMHnOC3ubOBiCZs/7fv8LIS7L32mayeaIqLWHxh0OQfB\n' \
        'ThrBnqEXfmacchmK8wWX0vKtcva8y/W+DBDFIREYKWMDetB9ZMT1jHLgo6AJOnE0\n' \
        'Hfxw1/hOjr8p1EBQzRz4wK+FbTQWiyByBBv/6wzarB4zP0ii9PV5NqotipJyD3Ux\n' \
        'g2LB+Bq6DCZRC4sq/WJQQVrcuth5n2N5dpjk//JZVP0+w9C2orUWQsN07DwwkjLf\n' \
        'x0yCcyW7+BgDu1TI+VzzHx1C+rP5GU03JCTfufeM8XP3idp1htEqAMXXXLPYLISX\n' \
        '-----END RSA PRIVATE KEY-----\n'


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
    return 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IjBoN1I4ZEwwclUtYjN' \
           'wM29uZnRfQlBmdVJXMUxkN1lqc0ZuT1dKdUZYVUUifQ.eyJ0ZXN0Ijoic29tZXR' \
           'oaW5nIiwiaWF0IjoxNjAyMjg4MDAwLCJuYmYiOjE2MDIyODgwMDAsImV4cCI6MT' \
           'YwMjI5MTYwMH0.N_RsiWGLXB57NxPPT2G4HaXokRlAzpDBazjWYQtfcOZo-8EX-' \
           'acLSJj8f006jWIwk29eF1yj96q-B5-0fmPgwsR7JwT-2HoiuoscZ1eYkRF5OIEG' \
           'aT3ebHs6Ootp039g6dmZK-P_fNpCQv5MyPPKwUEGZJ3yzav9uXajrkGdU9AKQs8' \
           'opKjB0m2XlIuTNTSNdGxTjwZSopYQpwObJeGbBA76Pe7HWZf6DCGSmlIpSkwO6Z' \
           'QdcBChYNPkIVttkMqC_RKE4bwFQU2oUc1Hdgmljhhg7IuZ9EjR5ZDoR8keMC1ih' \
           'DT10e4sFY2JUqKuqRhNEa2p6EnzysXpFGT6C5l9Xw'


@pytest.fixture
def test_certificate():
    cert = \
        b'-----BEGIN CERTIFICATE-----\n' \
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
    return cert


@pytest.fixture
def test_jwks():
    return {
        'alg': 'RS256',
        'e': 'AQAB',
        'kid': 'test-key',
        'kty': 'RSA',
        'n': '1LtU2hUlTSRC32IlfvtWQwG60P35aK-uFzsCvUSLc2Kr5xFFNfmh8OELwzci'
             'ibMh-_7qr-Nrw2YgogB-k9UVSw99AHSLMDkKVUrEHDxF3CX5CCd2UElqbk1T'
             'G7ybpK1ivUnDxZFMgQuxaZGf0SeqcIhNp1R43K8rAJitvygdR5PzZjvn8Hry'
             'HGF8K8TS5vZOlzOcciXJe2StxiJ2W7hHB-DXUWJwKO3Qi7bsERVFuH4EkVI48'
             'RVxiS3fN9Ig4B8zNFck6u-4MyqZ-VRGWyLw1oHPKMSh7KySm8r91BngtKtOCt'
             'hEEerau9YG0v4b_UAsZkesoDaqvG89HbJmV3nmMQ'
    }
