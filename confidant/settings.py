import base64
import json
import yaml
import logging
from os import getenv

from cryptography.fernet import Fernet

from confidant.lib import cryptolib


class SettingsError(Exception):
    pass


def bool_env(var_name, default=False):
    """
    Get an environment variable coerced to a boolean value.
    Example:
        Bash:
            $ export SOME_VAL=True
        settings.py:
            SOME_VAL = bool_env('SOME_VAL', False)
    Arguments:
        var_name: The name of the environment variable.
        default: The default to use if `var_name` is not specified in the
                 environment.
    Returns: `var_name` or `default` coerced to a boolean using the following
        rules:
            "False", "false" or "" => False
            Any other non-empty string => True
    """
    test_val = getenv(var_name, default)
    # Explicitly check for 'False', 'false', and '0' since all non-empty
    # string are normally coerced to True.
    if test_val in ('False', 'false', '0'):
        return False
    return bool(test_val)


def float_env(var_name, default=0.0):
    """
    Get an environment variable coerced to a float value.
    This has the same arguments as bool_env. If a value cannot be coerced to a
    float, a ValueError will be raised.
    """
    return float(getenv(var_name, default))


def int_env(var_name, default=0):
    """
    Get an environment variable coerced to an integer value.
    This has the same arguments as bool_env. If a value cannot be coerced to an
    integer, a ValueError will be raised.
    """
    return int(getenv(var_name, default))


def str_env(var_name, default=''):
    """
    Get an environment variable as a string.
    This has the same arguments as bool_env.
    """
    return getenv(var_name, default)


def _bootstrap(secrets):
    """
    Decrypt secrets and return a dict of secrets.
    """
    if not secrets:
        logging.info('SECRETS_BOOTSTRAP not set, skipping bootstrapping.')
        return {}
    if secrets.startswith('file://'):
        try:
            with open(secrets[7:], 'r') as f:
                _secrets = json.load(f)
        except IOError:
            logging.error(
                'Failed to load file specified in SECRETS_BOOTSTRAP.'
            )
            return {}
    else:
        _secrets = json.loads(secrets)
    key = cryptolib.decrypt_datakey(
        base64.b64decode(_secrets['data_key']),
        {'type': 'bootstrap'}
    )
    f = Fernet(key)
    decrypted_secrets = yaml.safe_load(
        f.decrypt(_secrets['secrets'].encode('utf-8'))
    )
    logging.info('Loaded SECRETS_BOOTSTRAP.')
    return decrypted_secrets


# Basic setup

# Whether or not Confidant is run in debug mode. Never run confidant in debug
# mode outside of development!
DEBUG = bool_env('DEBUG', False)
# The host the WSGI app should use.
HOST = str_env('HOST', '127.0.0.1')
# The port the WSGI app should use.
PORT = int_env('PORT', 8080)
# The directory to use for static content. To use minified resources, set this
# to 'dist'.
STATIC_FOLDER = str_env('STATIC_FOLDER', 'public')

# Bootstrapping

# A base64 encoded and KMS encrypted YAML string that contains secrets that
# confidant should use for its own secrets. The blob should be generated using
# confidant's generate_secrets_bootstrap script via manage.py. It uses the
# KMS_MASTER_KEY for decryption.
# If SECRETS_BOOTSTRAP starts with file://, then it will load the blob from a
# file, rather than reading the blob from the environment.
SECRETS_BOOTSTRAP = str_env('SECRETS_BOOTSTRAP')

_secrets_bootstrap = _bootstrap(SECRETS_BOOTSTRAP)

# User authentication method switcher.
# Supported methods:
# - 'google' # Google OAuth
# - 'saml'   # SAML Identity Provider
# - 'header' # Header-based authentication
USER_AUTH_MODULE = str_env('USER_AUTH_MODULE', 'google')

# An email suffix that can be used to restrict access to the web interface.
# Example: @example.com
# For backwards compatibility, also support setting this with
# GOOGLE_AUTH_EMAIL_SUFFIX.
USER_EMAIL_SUFFIX = (str_env('USER_EMAIL_SUFFIX', None) or
                     str_env('GOOGLE_AUTH_EMAIL_SUFFIX', None))

# A yaml file, with email: name mappings that can be used for restricting
# access to the web interface. If this file is not set, then any user with
# google/saml authentication access will be able to access/modify secrets.
USERS_FILE = str_env('USERS_FILE')

# SAML authentication
# SP: Service Provider (i.e. Confidant)
# IdP: Identity Provider
#
# When configuring SAML, the SAML_CONFIDANT_URL_ROOT is required. Other
# configuration options are mostly used to populate the settings dict passed to
# OneLogin_Saml2_Auth() for initialization. It is recommended to use the
# various individual configuration flags, but if you know what you're doing and
# need to configure more items in detail, use SAML_RAW_JSON_SETTINGS.

# Root URL that browsers use to hit Confidant,
# e.g. https://confidant.example.com/
SAML_CONFIDANT_URL_ROOT = str_env('SAML_CONFIDANT_URL_ROOT')

# Debug mode for python-saml library. Follows global DEBUG setting if not set.
SAML_DEBUG = bool_env('SAML_DEBUG', None)

# Pretend that all requests are HTTPS for purposes of SAML validation. This is
# useful if your app is behind a weird load balancer and flask isn't respecting
# X-Forwarded-Proto. For security, this flag will only be respected in debug
# mode.
SAML_FAKE_HTTPS = bool_env('SAML_FAKE_HTTPS', False)

# Path to SP X.509 certificate file in PEM format
SAML_SP_CERT_FILE = str_env('SAML_SP_CERT_FILE')
# Raw X.509 certificate in PEM format
SAML_SP_CERT = str_env('SAML_SP_CERT')

# Path to SP private key file in PEM format
SAML_SP_KEY_FILE = str_env('SAML_SP_KEY_FILE')
# Password for the SAML_SP_KEY_FILE
# This setting can be loaded from the SECRETS_BOOTSTRAP.
SAML_SP_KEY_FILE_PASSWORD = _secrets_bootstrap.get(
    'SAML_SP_KEY_FILE_PASSWORD',
    str_env('SAML_SP_KEY_FILE_PASSWORD', None)
)
# Raw SP private key in PEM format
# This setting can be loaded from the SECRETS_BOOTSTRAP.
SAML_SP_KEY = _secrets_bootstrap.get(
    'SAML_SP_KEY',
    str_env('SAML_SP_KEY')
)

# SAML IdP Entity ID (typically a URL)
SAML_IDP_ENTITY_ID = str_env('SAML_IDP_ENTITY_ID')
# SAML IdP Single Sign On URL (HTTP-REDIRECT binding only)
SAML_IDP_SIGNON_URL = str_env('SAML_IDP_SIGNON_URL')
# SAML IdP Single Logout URL, optional, only if IDP supports it
# (HTTP-REDIRECT binding only)
SAML_IDP_LOGOUT_URL = str_env('SAML_IDP_LOGOUT_URL')

# SAML IdP X.509 certificate in PEM format
SAML_IDP_CERT = str_env('SAML_IDP_CERT')
# SAML IdP X.509 certificate file in PEM format
SAML_IDP_CERT_FILE = str_env('SAML_IDP_CERT_FILE')

# SAML security settings. You will very likely want at least one of
# SAML_SECURITY_MESSAGES_SIGNED or SAML_SECURITY_ASSERTIONS_SIGNED to be True.
#
# Algorithm used for SAML signing
# default: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
# see also: http://www.w3.org/2000/09/xmldsig#rsa-sha1
SAML_SECURITY_SIG_ALGO = str_env(
    'SAML_SECURITY_SIG_ALGO',
    'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256')
# Whether to require signatures on SLO responses
SAML_SECURITY_SLO_RESP_SIGNED = bool_env('SAML_SECURITY_SLO_RESP_SIGNED', True)
# Whether to require signatures on full SAML response messages
SAML_SECURITY_MESSAGES_SIGNED = bool_env('SAML_SECURITY_MESSAGES_SIGNED', True)
# Whether to require signatures on individual SAML response assertion fields
SAML_SECURITY_ASSERTIONS_SIGNED = bool_env('SAML_SECURITY_ASSERTIONS_SIGNED',
                                           False)
# Whether you want an attribute statement from the SAML assertion
SAML_WANT_ATTRIBUTE_STATEMENT = bool_env('SAML_WANT_ATTRIBUTE_STATEMENT', True)

# Catchall to provide JSON directly to override SAML settings. Will be provided
# to OneLogin_Saml2_Auth() for initialization, merging into values set by the
# other SAML settings.
SAML_RAW_JSON_SETTINGS = json.loads(str_env('SAML_RAW_JSON_SETTINGS', 'null'))

# Google authentication

# The Google OAuth2 redirect URI endpoint URL.
REDIRECT_URI = str_env('REDIRECT_URI')
# The client ID provided by Google's developer console.
# This setting can be loaded from the SECRETS_BOOTSTRAP.
GOOGLE_OAUTH_CLIENT_ID = _secrets_bootstrap.get(
    'GOOGLE_OAUTH_CLIENT_ID',
    str_env('GOOGLE_OAUTH_CLIENT_ID')
)
# The consumer secret provided by Google's developer console.
# This setting can be loaded from the SECRETS_BOOTSTRAP.
GOOGLE_OAUTH_CONSUMER_SECRET = _secrets_bootstrap.get(
    'GOOGLE_OAUTH_CONSUMER_SECRET',
    str_env('GOOGLE_OAUTH_CONSUMER_SECRET')
)
# A randomly generated string that can be used as a salt for the OAuth2 flow.
# This setting can be loaded from the SECRETS_BOOTSTRAP.
AUTHOMATIC_SALT = _secrets_bootstrap.get(
    'AUTHOMATIC_SALT',
    str_env('AUTHOMATIC_SALT')
)

# Header-based authentication

# The name of the header that will contain the username.  Required if using
# header authentication.
HEADER_AUTH_USERNAME_HEADER = str_env('HEADER_AUTH_USERNAME_HEADER')
# The name of the header that will contain the user's email.  Required if using
# header authentication.
HEADER_AUTH_EMAIL_HEADER = str_env('HEADER_AUTH_EMAIL_HEADER')
# The name of the header that will contain the user's first name.  Optional.
HEADER_AUTH_FIRST_NAME_HEADER = str_env('HEADER_AUTH_FIRST_NAME_HEADER')
# The name of the header that will contain the user's last name.  Optional.
HEADER_AUTH_LAST_NAME_HEADER = str_env('HEADER_AUTH_LAST_NAME_HEADER')


# KMS service authentication

# The 'to' context used in KMS auth. This should be set to the name of the IAM
# role of the confidant server.
AUTH_CONTEXT = str_env('AUTH_CONTEXT')
# The alias of the KMS key being used for authentication. This can be the same
# as KMS_MASTER_KEY, but it's highly recommended to use a different key for
# authentication and at-rest encryption. This key is specifically for the
# 'service' role.
# Example: mykmskey
AUTH_KEY = str_env('AUTH_KEY')
# A dict of KMS key to account mappings. These keys are for the 'service' role
# to support multiple AWS accounts. If services are scoped to accounts,
# confidant will ensure the service authentication KMS auth used the mapped
# key. The account values in this setting will be shown to the user when
# creating or editing services.
# Example: {"sandbox-auth-key":"sandbox","primary-auth-key":"primary"}
SCOPED_AUTH_KEYS = json.loads(str_env('SCOPED_AUTH_KEYS', '{}'))
# The alias of the KMS key being used for authentication that is specifically
# for the 'user' role. This should not be the same key as AUTH_KEY if your
# kms token version is < 2, as it would allow services to masquerade as users.
USER_AUTH_KEY = str_env('USER_AUTH_KEY')
# The maximum lifetime of an authentication token in minutes.
AUTH_TOKEN_MAX_LIFETIME = int_env('AUTH_TOKEN_MAX_LIFETIME', 60)
# The maximum version of the authentication token accepted.
KMS_MAXIMUM_TOKEN_VERSION = int_env('KMS_MAXIMUM_TOKEN_VERSION', 2)
# The minimum version of the authentication token accepted.
KMS_MINIMUM_TOKEN_VERSION = int_env('KMS_MINIMUM_TOKEN_VERSION', 1)
# Comma separated list of user types allowed to auth via KMS.
KMS_AUTH_USER_TYPES = str_env('KMS_AUTH_USER_TYPES', 'service').split(',')
# Manage auth key grants for service to service authentication.
KMS_AUTH_MANAGE_GRANTS = bool_env('KMS_AUTH_MANAGE_GRANTS', True)
# Number of tokens to cache for authentication. This should be roughly
# equivalent to the number of tokens you expect to generate within the lifetime
# of your tokens.
KMS_AUTH_TOKEN_CACHE_SIZE = int_env('KMS_AUTH_TOKEN_CACHE_SIZE', 4096)

# SSL redirection and HSTS

# Whether or not to redirect to https and to set HSTS. It's highly recommended
# to run confidant with HTTPS or behind an ELB with SSL termination enabled.
SSLIFY = bool_env('SSLIFY', True)

# Cookie settings

# Cookie name for the session.
SESSION_COOKIE_NAME = str_env('SESSION_COOKIE_NAME', 'confidant_session')

# Cookie name for the XSRF token
XSRF_COOKIE_NAME = str_env('XSRF_COOKIE_NAME', 'XSRF-TOKEN')

# Session cache
# Mutually exclusive with secure cookie session settings.

# A redis connection url.
# Example: redis://localhost:6379
REDIS_URL = str_env('REDIS_URL')
# The session type for Flask-Session. Currenty only redis is supported.
SESSION_TYPE = str_env('SESSION_TYPE', 'redis')
# The key prefix to use in redis. Can be used to run multiple applications on
# the same redis server.
SESSION_KEY_PREFIX = str_env('SESSION_KEY_PREFIX', 'confidant:')
# Whether or not to sign the session cookie sid; see the Flask-Session docs
# for more information:
#   http://pythonhosted.org/Flask-Session/#configuration
SESSION_USE_SIGNER = bool_env('SESSION_USE_SIGNER', True)
# A long randomly generated string.
# This setting can be loaded from the SECRETS_BOOTSTRAP.
SESSION_SECRET = _secrets_bootstrap.get(
    'SESSION_SECRET',
    str_env('SESSION_SECRET')
)

# Secure cookie sessions
# Mutually exclusive with session cache settings

# Set a lifetime for a session, making sessions use 'permanent' cookies, rather
# than cookie being set as 'session' cookie. Cookies will last only as long as
# the lifetime of the session, rather than being cleared by the browser, which
# depending on the browser (and its user's configuration) can also be
# permanent. User actions will extend the permanent session lifetime, so this
# setting can be relatively small. Default is 43200 seconds (12 hours).
# To disable permanent cookies, set this to 0.
PERMANENT_SESSION_LIFETIME = int_env('PERMANENT_SESSION_LIFETIME', 43200)
# Set a maximum lifetime of a session, when using 'permanent' cookies. User
# actions extend the lifetime of a session cookie, but they will not be
# extended past this maximum time. This setting should be equal to or larger
# than PERMANENT_SESSION_LIFETIME. If unset, MAX_PERMANENT_SESSION_LIFETIME
# will be equal to PERMANENT_SESSION_LIFETIME. Default is 86400 seconds (24
# hours).
MAX_PERMANENT_SESSION_LIFETIME = int_env(
    'MAX_PERMANENT_SESSION_LIFETIME',
    86400
)

# General storage

# Set the DynamoDB to something non-standard. This can be used for local
# development. Doesn't normally need to be set.
# Example: http://localhost:8000
DYNAMODB_URL = str_env('DYNAMODB_URL')
# The DynamoDB table to use for storage.
# Example: mydynamodbtable
DYNAMODB_TABLE = str_env('DYNAMODB_TABLE')
# Have PynamoDB automatically generate the DynamoDB table if it doesn't exist.
# Note that you need to give Confidant's IAM user or role enough privileges for
# this to occur.
DYNAMODB_CREATE_TABLE = bool_env('DYNAMODB_CREATE_TABLE', False)
# Connection pool size for PynamoDB connections to DynamoDB
PYNAMO_CONNECTION_POOL_SIZE = int_env('PYNAMO_CONNECTION_POOL_SIZE', 100)
PYNAMO_REQUEST_TIMEOUT_SECONDS = int_env('PYNAMO_REQUEST_TIMEOUT_SECONDS', 1)

# Encryption

# The KMS key to use for at-rest encryption for secrets in DynamoDB.
KMS_MASTER_KEY = str_env('KMS_MASTER_KEY')

# Graphite events

# A graphite events URL.
# Example: https://graphite.example.com/events/
GRAPHITE_EVENT_URL = str_env('GRAPHITE_EVENT_URL')
# A basic auth username.
# Example: mygraphiteuser
# This setting can be loaded from the SECRETS_BOOTSTRAP.
GRAPHITE_USERNAME = _secrets_bootstrap.get(
    'GRAPHITE_USERNAME',
    str_env('GRAPHITE_USERNAME')
)
# A basic auth password:
# Example: mylongandsupersecuregraphitepassword
# This setting can be loaded from the SECRETS_BOOTSTRAP.
GRAPHITE_PASSWORD = _secrets_bootstrap.get(
    'GRAPHITE_PASSWORD',
    str_env('GRAPHITE_PASSWORD')
)

# Statsd metrics

# A statsd host
STATSD_HOST = str_env('STATSD_HOST', 'localhost')
# A statsd port
STATSD_PORT = int_env('STATSD_PORT', 8125)

# Webhook configuration

# Endpoint URL to send webhook events to.
WEBHOOK_URL = str_env('WEBHOOK_URL')
# A basic auth username.
# Example: myhookuser
# This setting can be loaded from the SECRETS_BOOTSTRAP.
WEBHOOK_USERNAME = _secrets_bootstrap.get(
    'WEBHOOK_USERNAME',
    str_env('WEBHOOK_USERNAME')
)
# A basic auth password:
# Example: mylongandsupersecurehookpassword
# This setting can be loaded from the SECRETS_BOOTSTRAP.
WEBHOOK_PASSWORD = _secrets_bootstrap.get(
    'WEBHOOK_PASSWORD',
    str_env('WEBHOOK_PASSWORD')
)

# Ignore conflicts of credential names in a service
# This is used if you don't mind having more than one of the same key name
# in different credentials associated with a service.
IGNORE_CONFLICTS = bool_env('IGNORE_CONFLICTS', False)


# Customization

# Directory for customization of AngularJS frontend.
CUSTOM_FRONTEND_DIRECTORY = str_env('CUSTOM_FRONTEND_DIRECTORY')

# Custom configuration to bootstrap confidant clients. This
# configuration is in JSON format and can contain anything you'd like to pass
# to the clients. Here's an example for passing default configuration for blind
# secrets to the opinionated CLI client:
#
# {
#   "blind_keys": {
#      "us-east-1": "alias/blindkey-useast1",
#      "us-west-2": "alias/blindkey-uswest2"
#    },
#    "blind_cipher_type": "fernet",
#    "blind_cipher_version": "2",
#    "blind_store_credential_keys": true
# }
CLIENT_CONFIG = json.loads(str_env('CLIENT_CONFIG', '{}'))

# Test/Development

# Whether or not authentication is required. Unless doing testing or
# development, this should always be set to True.
USE_AUTH = bool_env('USE_AUTH', True)
# A boolean to enable/disable encryption. This is meant to be used for
# test and development only. If this is disabled it will store unencrypted
# content, rather than encrypted content. This allows you to test
# or do development of features without a KMS key. Even for test and
# development purposes, it's possible to avoid using this setting, by exposing
# AWS credentials to Confidant and giving it access to a KMS key.
# DO NOT DISABLE THIS EXCEPT FOR TEST AND DEVELOPMENT PURPOSES!
USE_ENCRYPTION = bool_env('USE_ENCRYPTION', True)

# boto3 configuration

# Timeout settings for connecting to KMS (see:
# https://botocore.readthedocs.io/en/stable/reference/config.html)
KMS_CONNECTION_TIMEOUT = int_env('KMS_CONNECTION_TIMEOUT', 1)
# Timeout settings for reading from KMS (see:
# https://botocore.readthedocs.io/en/stable/reference/config.html)
KMS_READ_TIMEOUT = int_env('KMS_READ_TIMEOUT', 1)
# Connection pool settings for connecting to KMS (see:
# https://botocore.readthedocs.io/en/stable/reference/config.html)
KMS_MAX_POOL_CONNECTIONS = int_env('KMS_MAX_POOL_CONNECTIONS', 100)

# Must be set to the region the server is running.
AWS_DEFAULT_REGION = str_env('AWS_DEFAULT_REGION', 'us-east-1')

# gevent configuration

# Note that it's important to set this environment variable, even though it
# isn't exposed in app.config.
# See: https://github.com/surfly/gevent/issues/468
#
# GEVENT_RESOLVER='ares'

# Configuration validation
_settings_failures = False
if len(list(set(SCOPED_AUTH_KEYS.values()))) != len(SCOPED_AUTH_KEYS.values()):
    logging.error('SCOPED_AUTH_KEYS values are not unique.')
    _settings_failures = True

if _settings_failures:
    raise SettingsError('Refusing to continue with invalid settings.')


def get(name, default=None):
    """
    Get the value of a variable in the settings module scope.
    """
    return globals().get(name, default)
