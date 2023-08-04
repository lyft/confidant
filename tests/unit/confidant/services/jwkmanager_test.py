import confidant.services.jwkmanager
import datetime
import base64
import json
import pytest
from jwcrypto import jwk
from pytest_mock.plugin import MockerFixture
from typing import Dict, Union
from unittest.mock import patch, Mock
from confidant.services.jwkmanager import JWKManager
from confidant.settings import JWT_CACHING_TTL_SECONDS


def test_set_key(test_key_pair: jwk.JWK):
    jwk_manager = JWKManager()
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    kid = jwk_manager.set_key('test',
                              'test-key',
                              test_private_key.decode('utf-8'))
    assert kid == 'test-key'


def test_set_key_encrypted(test_encrypted_key: str):
    jwk_manager = JWKManager()
    kid = jwk_manager.set_key('test', 'test-key', test_encrypted_key,
                              passphrase='123456')
    assert kid == 'test-key'


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt(
    mocker: MockerFixture,
    test_key_pair: jwk.JWK,
    test_jwk_payload: Dict[str, Union[str, bool]],
    test_jwt: str
):
    jwk_manager = JWKManager()
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
    )
    jwk_manager.set_key('test',
                        test_key_pair.thumbprint(),
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwt('test', test_jwk_payload)
    assert result == test_jwt


def helper_jwt_parser(jwt_str, field):
    payload_str = f"{jwt_str.split('.')[1]}="
    payload_dict = json.loads(base64.b64decode(payload_str))
    return payload_dict[field]


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_CACHING_ENABLED', True)
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt_caches_jwt(
    mocker: MockerFixture,
    test_key_pair: jwk.JWK,
    test_jwk_payload: Dict[str, Union[str, bool]],
    test_jwt: str
):
    jwk_manager = JWKManager()
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    jwk_manager.set_key('test',
                        test_key_pair.thumbprint(),
                        test_private_key.decode('utf-8'))
    base_time = datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=base_time
    )
    # hydrate cache
    result = jwk_manager.get_jwt('test', test_jwk_payload)

    # only 1 minute has elapsed, cache should hit
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=base_time + datetime.timedelta(seconds=60)
    )
    cached_result = jwk_manager.get_jwt('test', test_jwk_payload)
    assert result == test_jwt
    assert result == cached_result
    assert 1602291600 == helper_jwt_parser(cached_result, 'exp')

    # test we CAN request from cache if time elapsed < JWT_CACHING_TTL_SECONDS
    elapsed_time = base_time + datetime.timedelta(
        seconds=JWT_CACHING_TTL_SECONDS-1
    )
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=elapsed_time
    )
    cached_result = jwk_manager.get_jwt('test', test_jwk_payload)
    assert result == cached_result
    assert 1602291600 == helper_jwt_parser(cached_result, 'exp')

    # test we CANNOT request from cache
    # if time elapsed >= JWT_CACHING_TTL_SECONDS
    # new token will be provisioned with new exp
    elapsed_time = base_time + datetime.timedelta(
        seconds=JWT_CACHING_TTL_SECONDS
    )
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=elapsed_time
    )
    cached_result = jwk_manager.get_jwt('test', test_jwk_payload)
    assert result != cached_result
    assert 1602292500 == helper_jwt_parser(cached_result, 'exp')

    # token has long expired, cache should NOT hit
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=base_time + datetime.timedelta(days=30)
    )
    cached_result = jwk_manager.get_jwt('test', test_jwk_payload)
    assert 1604883600 == helper_jwt_parser(cached_result, 'exp')


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_CACHING_ENABLED', False)
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt_does_not_cache_jwt(
    mocker: MockerFixture,
    test_key_pair: jwk.JWK,
    test_jwk_payload: Dict[str, Union[str, bool]],
    test_jwt: str
):
    jwk_manager = JWKManager()
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=0,
            second=0,
            microsecond=0
        )
    )
    jwk_manager.set_key('test',
                        test_key_pair.thumbprint(),
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwt('test', test_jwk_payload)

    mocker.patch(
        'confidant.services.jwkmanager.datetime.now',
        return_value=datetime.datetime(
            year=2020,
            month=10,
            day=10,
            hour=0,
            minute=1,
            second=1,
            microsecond=0
        )
    )

    not_cached_result = jwk_manager.get_jwt('test', test_jwk_payload)
    assert result == test_jwt
    assert result != not_cached_result


def test_get_jwt_raises_no_key_id(
    test_key_pair: jwk.JWK,
    test_jwk_payload: Dict[str, Union[str, bool]]
):
    jwk_manager = JWKManager()
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    jwk_manager.set_key('test', 'test-key', test_private_key.decode('utf-8'))
    with pytest.raises(ValueError, match='No active key for this environment'):
        jwk_manager.get_jwt('non-existent', test_jwk_payload)


def test_get_jwks(
    test_key_pair: jwk.JWK,
    test_jwks: Dict[str, str]
):
    jwk_manager = JWKManager()
    test_private_key = test_key_pair.export_to_pem(private_key=True,
                                                   password=None)
    jwk_manager.set_key('testing',
                        '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE',
                        test_private_key.decode('utf-8'))
    result = jwk_manager.get_jwks('testing')
    assert len(result) == 1
    assert result[0] == test_jwks


def test_get_jwks_not_found():
    jwk_manager = JWKManager()
    result = jwk_manager.get_jwks('non-existent')
    assert not result


@patch.object(confidant.services.jwkmanager, 'datetime',
              Mock(wraps=datetime.datetime))
@patch.object(confidant.services.jwkmanager, 'JWT_ACTIVE_SIGNING_KEYS',
              {'test': '0h7R8dL0rU-b3p3onft_BPfuRW1Ld7YjsFnOWJuFXUE'})
def test_get_jwt_with_ca(
    mocker: MockerFixture,
    test_jwk_payload: Dict[str, Union[str, bool]],
    test_jwt: str,
    test_certificate_authorities: str
):
    with patch.object(confidant.services.jwkmanager,
                      'JWT_CERTIFICATE_AUTHORITIES',
                      test_certificate_authorities):

        jwk_manager = JWKManager()
        mocker.patch(
            'confidant.services.jwkmanager.datetime.now',
            return_value=datetime.datetime(
                year=2020,
                month=10,
                day=10,
                hour=0,
                minute=0,
                second=0,
                microsecond=0
            )
        )
        result = jwk_manager.get_jwt('test', test_jwk_payload)
        assert result == test_jwt
