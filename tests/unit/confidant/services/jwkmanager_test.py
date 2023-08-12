import confidant.services.jwkmanager
import datetime
import base64
import json
import pytest
import fakeredis
from redis import RedisError

from jwcrypto import jwk
from pytest_mock.plugin import MockerFixture
from typing import Dict, Union
from unittest.mock import patch, Mock
from confidant.services.jwkmanager import JWKManager
from confidant.services.jwkmanager import LocalJwtCache, RedisCache
from confidant.settings import JWT_CACHING_MAX_SIZE
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

    # Test enabling caching
    mocker.patch.object(confidant.services.jwkmanager,
                        'JWT_CACHING_ENABLED', True)
    # Test that if cache doesn't return a jwt, we call set_jwt
    local_cache_get_mock = mocker.patch.object(
        jwk_manager,
        '_jwt_cache'
    )
    local_cache_get_mock.get_jwt.return_value = None
    jwk_manager.get_jwt('test', test_jwk_payload)
    assert local_cache_get_mock.get_jwt.called is True
    assert local_cache_get_mock.set_jwt.called is True

    # Test that if cache returns a jwt, we don't call set_jwt
    local_cache_get_mock = mocker.patch.object(
        jwk_manager,
        '_jwt_cache'
    )
    local_cache_get_mock.get_jwt.return_value = test_jwt
    jwk_manager.get_jwt('test', test_jwk_payload)
    assert local_cache_get_mock.get_jwt.called is True
    assert local_cache_get_mock.set_jwt.called is False

    # Test cache disabled
    mocker.patch.object(confidant.services.jwkmanager,
                        'JWT_CACHING_ENABLED', False)
    local_cache_get_mock = mocker.patch.object(
        jwk_manager,
        '_jwt_cache'
    )
    local_cache_get_mock.get_jwt.return_value = None
    jwk_manager.get_jwt('test', test_jwk_payload)
    assert local_cache_get_mock.get_jwt.called is False
    assert local_cache_get_mock.set_jwt.called is False

    # Test that if cache returns a jwt, we don't call set_jwt
    local_cache_get_mock = mocker.patch.object(
        jwk_manager,
        '_jwt_cache'
    )
    local_cache_get_mock.get_jwt.return_value = test_jwt
    jwk_manager.get_jwt('test', test_jwk_payload)
    assert local_cache_get_mock.get_jwt.called is False
    assert local_cache_get_mock.set_jwt.called is False


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


def test_localcache_init():
    localcache = LocalJwtCache()
    assert localcache._token_cache.maxsize == JWT_CACHING_MAX_SIZE
    assert localcache._token_cache.ttl == JWT_CACHING_TTL_SECONDS
    assert len(localcache._token_cache) == 0


def test_localcache_cache_key():
    localcache = LocalJwtCache()
    result = localcache.cache_key('marge', 'homer', 'bart')
    assert result == 'marge:homer:bart'


def test_localcache_get_jwt():
    localcache = LocalJwtCache()
    cached_jwt = localcache.get_jwt('marge', 'homer', 'bart')
    assert cached_jwt is None
    assert len(localcache._token_cache) == 0

    cached_jwt = localcache.set_jwt('marge', 'homer', 'bart', 'lisa')
    cached_jwt = localcache.get_jwt('marge', 'homer', 'bart')
    assert cached_jwt == 'lisa'
    assert len(localcache._token_cache) == 1


@patch('confidant.services.jwkmanager.StrictRedis',
       fakeredis.FakeStrictRedis)
@patch.object(confidant.services.jwkmanager, 'REDIS_URL',
              'redis://localhost:9090')
def test_rediscache_get_jwt():
    redis_cache = RedisCache()
    cached_jwt = redis_cache.get_jwt('marge', 'homer', 'bart')
    assert cached_jwt is None
    redis_cache.set_jwt('marge', 'homer', 'bart', 'lisa')
    cached_jwt = redis_cache.get_jwt('marge', 'homer', 'bart')
    assert cached_jwt == 'lisa'


@patch('confidant.services.jwkmanager.StrictRedis.get',
       side_effect=RedisError("Mocked RedisError"))
@patch.object(confidant.services.jwkmanager, 'REDIS_URL',
              'redis://localhost:9090')
def test_rediscache_redis_error(mock_redis):
    redis_cache = RedisCache()
    cached_jwt = redis_cache.get_jwt('marge', 'homer', 'bart')
    assert cached_jwt is None
