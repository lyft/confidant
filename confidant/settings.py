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

# Google authentication

# A yaml file, with email: name mappings that can be used for restricting
# access to the web interface. If this file is not set, then any user with
# google authentication access will be able to access/modify secrets.
USERS_FILE = str_env('USERS_FILE')
# The Google OAuth2 redirect URI endpoint URL.
REDIRECT_URI = str_env('REDIRECT_URI')
# An email suffix that can be used to restrict access to the web interface.
# Example: @example.com
GOOGLE_AUTH_EMAIL_SUFFIX = str_env('GOOGLE_AUTH_EMAIL_SUFFIX', '')
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
# authentication and at-rest encryption.
# Example: mykmskey
AUTH_KEY = str_env('AUTH_KEY')
# The maximum lifetime of an authentication token in minutes.
AUTH_TOKEN_MAX_LIFETIME = int_env('AUTH_TOKEN_MAX_LIFETIME', 60)

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

# Note that it's important to set this environment variable, even though it
# isn't exposed in app.config. Must be set to the region the server is running
# in.
#
# AWS_DEFAULT_REGION='us-east-1'

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
