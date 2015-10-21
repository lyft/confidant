# Make the tests directory a python module
# so that all unit tests are reported as part of the tests package.

import os

# Inject mandatory environment variables

os.environ['REGION'] = os.getenv('REGION', 'us-east-1')
os.environ['SESSION_SECRET'] = os.getenv('SESSION_SECRET', 'secret')
# Use a separate table for unit tests so local unittests don't alter your
# development environment. This table will be frequently deleted and created
# multiple times.
os.environ['DYNAMODB_TABLE'] = os.getenv(
    'DYNAMODB_TESTING_TABLE',
    'confidant-testing'
)
