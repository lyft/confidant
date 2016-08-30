# Make the tests directory a python module
# so that all unit tests are reported as part of the tests package.

import os

# Inject mandatory environment variables

env_settings = [
    ('SESSION_SECRET', 'secret'),
    ('DYNAMODB_TABLE', 'confidant-testing'),
    ('DYNAMODB_URL', 'http://dynamo:7777'),
    ('DYNAMODB_CREATE_TABLE', 'false'),
    ('GEVENT_RESOLVER', 'ares'),
    ('AWS_DEFAULT_REGION', 'us-east-1'),
    ('USER_AUTH_KEY', 'authnz-usertesting'),
    ('AUTH_KEY', 'authnz-testing'),
    ('SCOPED_AUTH_KEYS',
     '{"sandbox-auth-key":"sandbox","primary-auth-key":"primary"}'),
    ('KMS_MASTER_KEY', 'confidant-mastertesting'),
    ('DEBUG', 'true'),
    ('STATIC_FOLDER', 'public')
]

for env_setting in env_settings:
    os.environ[env_setting[0]] = os.getenv(env_setting[0], env_setting[1])
