import pytest

from confidant.services.jwkmanager import jwk_manager


class TestJWKManager:
    def test_set_key(self, test_key_pair):
        test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                       password=None)
        kid = jwk_manager.set_key('test-key', test_private_key.decode('utf-8'))
        assert kid == 'test-key'

    def test_get_jwt(self, test_key_pair, test_jwk_payload, test_jwt):
        test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                       password=None)
        jwk_manager.set_key(test_key_pair.thumbprint(),
                            test_private_key.decode('utf-8'))
        result = jwk_manager.get_jwt(test_key_pair.thumbprint(),
                                     test_jwk_payload)
        assert result == test_jwt

    def test_get_jwt_raises_no_key_id(self, test_key_pair, test_jwk_payload):
        test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                       password=None)
        jwk_manager.set_key('test-key', test_private_key.decode('utf-8'))
        with pytest.raises(ValueError, match='This private key is not stored'):
            jwk_manager.get_jwt('non-existent', test_jwk_payload)

    def test_get_payload(self, test_key_pair, test_jwk_payload, test_jwt,
                         test_certificate):
        test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                       password=None)
        jwk_manager.set_key('test-key', test_private_key.decode('utf-8'))
        result = jwk_manager.get_payload(test_certificate.decode('utf-8'),
                                         test_jwt)
        assert result == test_jwk_payload

    def test_get_jwks(self, test_key_pair, test_jwk_payload, test_jwt,
                      test_jwks):
        test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                       password=None)
        jwk_manager.set_key('test-key', test_private_key.decode('utf-8'))
        result = jwk_manager.get_jwks('test-key')
        assert result == test_jwks

    def test_get_jwks_not_found(self, test_key_pair, test_jwk_payload, test_jwt):
        result = jwk_manager.get_jwks('non-existent')
        assert not result
