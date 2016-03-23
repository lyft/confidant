import json
from os import getenv


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


# Basic setup

# Whether or not Confidant is run in debug mode. Never run confidant in debug
# mode outside of development!
DEBUG = bool_env('DEBUG', False)
# The port the WSGI app should use.
PORT = int_env('PORT', 8080)
# The directory to use for static content. To use minified resources, set this
# to 'dist'.
STATIC_FOLDER = str_env('STATIC_FOLDER', 'public')

APPLICATION_ENV = str_env('APPLICATION_ENV', 'development')

# User authentication method switcher.
# Supported methods:
# - 'google' # Google OAuth
# - 'saml'   # SAML Identity Provider
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
# Raw X.509 certificate in base64-encoded DER
SAML_SP_CERT = str_env('SAML_SP_CERT')

# Path to SP private key file in PEM format
SAML_SP_KEY_FILE = str_env('SAML_SP_KEY_FILE')
# Password for the SAML_SP_KEY_FILE
SAML_SP_KEY_FILE_PASSWORD = str_env('SAML_SP_KEY_FILE_PASSWORD', None)
# Raw SP private key in base64-encoded DER
SAML_SP_KEY = str_env('SAML_SP_KEY')

# SAML IdP Entity ID (typically a URL)
SAML_IDP_ENTITY_ID = str_env('SAML_IDP_ENTITY_ID')
# SAML IdP Single Sign On URL (HTTP-REDIRECT binding only)
SAML_IDP_SIGNON_URL = str_env('SAML_IDP_SIGNON_URL')
# SAML IdP Single Logout URL, optional, only if IDP supports it
# (HTTP-REDIRECT binding only)
SAML_IDP_LOGOUT_URL = str_env('SAML_IDP_LOGOUT_URL')

# SAML IdP X.509 certificate, base64 encoded DER
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

# Catchall to provide JSON directly to override SAML settings. Will be provided
# to OneLogin_Saml2_Auth() for initialization, merging into values set by the
# other SAML settings.
SAML_RAW_JSON_SETTINGS = json.loads(str_env('SAML_RAW_JSON_SETTINGS', 'null'))

# Google authentication

# The Google OAuth2 redirect URI endpoint URL.
REDIRECT_URI = str_env('REDIRECT_URI')
# The client ID provided by Google's developer console.
GOOGLE_OAUTH_CLIENT_ID = str_env('GOOGLE_OAUTH_CLIENT_ID')
# The consumer secret provided by Google's developer console.
GOOGLE_OAUTH_CONSUMER_SECRET = str_env('GOOGLE_OAUTH_CONSUMER_SECRET')
# A randomly generated string that can be used as a salt for the OAuth2 flow.
AUTHOMATIC_SALT = str_env('AUTHOMATIC_SALT')

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
# The alias of the KMS key being used for authentication that is specifically
# for the 'user' role. This should not be the same key as AUTH_KEY if your
# kms token version is < 2, as it would allow services to masquerade as users.
USER_AUTH_KEY = str_env('USER_AUTH_KEY')
# The maximum lifetime of an authentication token in minutes.
AUTH_TOKEN_MAX_LIFETIME = int_env('AUTH_TOKEN_MAX_LIFETIME', 60)
# The minimum version of the authentication token accepted.
KMS_MAXIMUM_TOKEN_VERSION = int_env('KMS_MAXIMUM_TOKEN_VERSION', 2)
# The maximum version of the authentication token accepted.
KMS_MINIMUM_TOKEN_VERSION = int_env('KMS_MINIMUM_TOKEN_VERSION', 1)
# Comma separated list of user types allowed to auth via KMS.
KMS_AUTH_USER_TYPES = str_env('KMS_AUTH_USER_TYPES', 'service').split(',')

# SSL redirection and HSTS

# Whether or not to redirect to https and to set HSTS. It's highly recommended
# to run confidant with HTTPS or behind an ELB with SSL termination enabled.
SSLIFY = bool_env('SSLIFY', True)

# Session cache

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
SESSION_SECRET = str_env('SESSION_SECRET')
# Whether or not the session cookie will be marked as permanent
SESSION_PERMANENT = bool_env('SESSION_PERMANENT', False)
# Cookie name for the session.
SESSION_COOKIE_NAME = str_env('SESSION_COOKIE_NAME', 'confidant_session')

# General storage

# Set the DynamoDB to something non-standard. This can be used for local
# development. Doesn't normally need to be set.
# Example: http://localhost:8000
DYNAMODB_URL = str_env('DYNAMODB_URL')
# The DynamoDB table to use for storage.
# Example: mydynamodbtable
DYNAMODB_TABLE = str_env('DYNAMODB_TABLE')

# Encryption

# The KMS key to use for at-rest encryption for secrets in DynamoDB.
KMS_MASTER_KEY = str_env('KMS_MASTER_KEY')

# Graphite events

# A graphite events URL.
# Example: https://graphite.example.com/events/
GRAPHITE_EVENT_URL = str_env('GRAPHITE_EVENT_URL')
# A basic auth username.
# Example: mygraphiteuser
GRAPHITE_USERNAME = str_env('GRAPHITE_USERNAME')
# A basic auth password:
# Example: mylongandsupersecuregraphitepassword
GRAPHITE_PASSWORD = str_env('GRAPHITE_PASSWORD')

# Statsd metrics

# A statsd host
STATSD_HOST = str_env('STATSD_HOST', 'localhost')
# A statsd port
STATSD_PORT = int_env('STATSD_PORT', 8125)

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

# Must be set to the region the server is running.
AWS_DEFAULT_REGION = str_env('AWS_DEFAULT_REGION', 'us-east-1')

# gevent configuration

# Note that it's important to set this environment variable, even though it
# isn't exposed in app.config.
# See: https://github.com/surfly/gevent/issues/468
#
# GEVENT_RESOLVER='ares'


def get(name, default=None):
    """
    Get the value of a variable in the settings module scope.
    """
    return globals().get(name, default)
