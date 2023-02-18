import confidant.services.jwkmanager
import datetime

import pytest

from unittest.mock import patch, Mock

from confidant.services.jwkmanager import jwk_manager


def test_set_key(test_key_pair):
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    kid = jwk_manager.set_key('test',
                              'test-key',
                              test_private_key.decode('utf-8'))
    assert kid == 'test-key'


def test_set_key_encrypted(test_encrypted_key):
    kid = jwk_manager.set_key('test', 'test-key', test_encrypted_key,
                              passphrase='123456')
    assert kid == 'test-key'


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt(test_key_pair, test_jwk_payload, test_jwt):
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    confidant.services.jwkmanager.datetime.now.return_value = \
        datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
    jwk_manager.set_key('test',
                        test_key_pair.thumbprint(),
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwt('test',
                                 test_jwk_payload)
    assert result == test_jwt


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_CACHING_ENABLED', True)
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt_caches_jwt(test_key_pair, test_jwk_payload, test_jwt):
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    confidant.services.jwkmanager.datetime.now.return_value = \
        datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
    jwk_manager.set_key('test',
                        test_key_pair.thumbprint(),
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwt('test',
                                 test_jwk_payload)

    confidant.services.jwkmanager.datetime.now.return_value = \
        datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=1,
            second=0,
            microsecond=0
        )
    cached_result = jwk_manager.get_jwt('test',
                                        test_jwk_payload)
    assert result == test_jwt
    assert result == cached_result


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_CACHING_ENABLED', False)
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt_does_not_cache_jwt(test_key_pair, test_jwk_payload, test_jwt):
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    confidant.services.jwkmanager.datetime.now.return_value = \
        datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
    jwk_manager.set_key('test',
                        test_key_pair.thumbprint(),
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwt('test',
                                 test_jwk_payload)

    confidant.services.jwkmanager.datetime.now.return_value = \
        datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=1,
            second=1,
            microsecond=0
        )
    not_cached_result = jwk_manager.get_jwt('test',
                                            test_jwk_payload)
    assert result == test_jwt
    assert result != not_cached_result


def test_get_jwt_raises_no_key_id(test_key_pair, test_jwk_payload):
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    jwk_manager.set_key('test', 'test-key', test_private_key.decode('utf-8'))
    with pytest.raises(ValueError, match='No active key for this environment'):
        jwk_manager.get_jwt('non-existent', test_jwk_payload)


def test_get_jwks(test_key_pair, test_jwk_payload, test_jwt,
                  test_jwks):
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    jwk_manager.set_key('testing',
                        '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE',
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwks('testing')
    assert len(result) == 1
    assert result[0] == test_jwks


def test_get_jwks_not_found(test_key_pair, test_jwk_payload,
                            test_jwt):
    result = jwk_manager.get_jwks('non-existent')
    assert not result


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt_with_ca(test_jwk_payload, test_jwt,
                         test_certificate_authorities):
    with patch.object(confidant.services.jwkmanager,
                      'JWT_CERTIFICATE_AUTHORITIES',
                      test_certificate_authorities):
        confidant.services.jwkmanager.datetime.now.return_value = \
            datetime.datetime(
                year=2020,
                month=10,
                day=10,
                hour=0,
                minute=0,
                second=0,
                microsecond=0
            )
        result = jwk_manager.get_jwt('test',
                                     test_jwk_payload)
    assert result == test_jwt
