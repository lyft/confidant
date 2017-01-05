---
title: Configuration
---

# Configuration

Confidant is primarily configured through environment variables. The list of
all available configuration options can be found in the settings.py file.

Prerequisites not covered by this guide:

1. Your Google application is setup and you know your client id and secret key.

## Docker vs bash

Note that below the format of the configuration is given in bash format for
defining and exporting environment variables. Docker environment files have a
slightly different format than bash. Here's an example of the difference:

In bash format:

```bash
export MY_VARIABLE='MY_VALUE'
```

In docker env file format, you don't export the variable, and the value
shouldn't be quoted, since everything after the equal sign is considered part
of the value. So, in a docker environment file, you'd define the same variable
and value like this:

In docker format:

```
MY_VARIABLE=MY_VALUE
```

## Basic environment configuration

This is the minimum configuration needed to use Confidant:

```bash
# The region our service is running in.
export AWS_DEFAULT_REGION='us-east-1'
# The IAM role name of the confidant server.
export AUTH_CONTEXT='confidant-production'
# The KMS key used for auth.
export AUTH_KEY='authnz-production'
# The DynamoDB table name for storage.
export DYNAMODB_TABLE='confidant-production'
# Auto-generate the dynamodb table.
export DYNAMODB_CREATE_TABLE=true
# Set the gevent resolver to ares; see:
#   https://github.com/surfly/gevent/issues/468
export GEVENT_RESOLVER='ares'
# The KMS key used for at-rest encryption in DynamoDB.
export KMS_MASTER_KEY='confidant-production'
# A long randomly generated string for CSRF protection.
# SESSION_SECRET can be loaded via SECRETS_BOOTSTRAP
export SESSION_SECRET='aBVmJA3zv6zWGjrYto135hkdox6mW2kOu7UaXIHK8ztJvT8w5O'
# The IP address to listen on.
export HOST='0.0.0.0'
# The port to listen on.
export PORT='80'
```

### Google authentication configuration

To enable Google authentication, you'll need to visit the API manager in the
Google developer console (https://console.developers.google.com), and create a
new project (or add credentials to an existing project, if you prefer). After
creating the project, you'll need to enable the Google+ API. After enabling the
Google+ API, you'll need to add credentials to this project. You'll want to
create OAuth client ID credentials. The application type is 'Web application'.
The Authorized JavaScript origins is '<url>/'. The Authorized redirect URI is 
`<url>/v1/login`. Take the generated client id and consumer secret, and set
them in the settings. You'll also need to generate a long random string and set
the AUTHOMATIC_SALT setting, for CSRF protection.

```bash
# The authentication type we'll be using for user authentication (google is the
# default)
export USER_AUTH_MODULE='google'
# The client id and consumer secret from the google developer console.
# GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CONSUMER_SECRET can be loaded via SECRETS_BOOTSTRAP
export GOOGLE_OAUTH_CLIENT_ID='123456789-abcdefghijklmnop.apps.googleusercontent.com'
export GOOGLE_OAUTH_CONSUMER_SECRET='123456789abcdefghijklmnop'
# A long randomly generated string used for the google OAuth2 flow.
# AUTHOMATIC_SALT can be loaded via SECRETS_BOOTSTRAP
export AUTHOMATIC_SALT='H39bfLCqLbrYrFyiJIxkK0uf12rlzvgjgo9FqOnttPXIdAAuyQ'
```

### SAML authentication configuration

TODO: As of Confidant version 1.1 it's possible to use SAML as an alternative
to google authentication. We still need to document all of the options, though.
Basic documentation for each SAML option is described in the settings.py file.

## Advanced environment configuration

### statsd metrics

Confidant can track some stats via statsd. By default it's set to send stats to
statsd on localhost on port 8125.

```bash
export STATSD_HOST='mystatshost.example.com'
export STATSD_PORT='8125'
```

### Sending graphite events

Confidant can also send graphite events on secret updates or changes in service
mappings:

```bash
export GRAPHITE_EVENT_URL='https://graphite.example.com/events/'
export GRAPHITE_USERNAME='mygraphiteuser'
# GRAPHITE_PASSWORD can be loaded via SECRETS_BOOTSTRAP
export GRAPHITE_PASSWORD='mylongandsupersecuregraphitepassword'
```

### Google authentication user restrictions

It's possible to restrict access to a subset of users that authenticate
using Google authentication:

```bash
export USERS_FILE='/etc/confidant/users.yaml'
export USER_EMAIL_SUFFIX='@example.com'
```

In the above configuration, Confidant will limit authentication to users with
the email domain @example.com. Additionally, Confidant will look in the
users.yaml file for a list of email addresses allowed to access Confidant.

### Auth token lifetime

It's possible to limit the lifetime of KMS authentication tokens. By default
Confidant limits token lifetime to 60 minutes, to ensure that tokens are being
rotated. To change this, you can use the following option:

```bash
# Limit token lifetime to 10 minutes.
export AUTH_TOKEN_MAX_LIFETIME='10'
```

### Frontend configuration

If you're using the generated, minified output in the dist directory, you
need to tell confidant to change its static folder:

```bash
export STATIC_FOLDER='dist'
```

It's possible to customize portions of the angularjs application.
Currently you can add a documentation section to the credential details view.
We'd like to make more customization available. Please open a github issue with
specific customizations you'd like focused on first. The custom js/css/html
will be served from a directory you specify:

```bash
export CUSTOM_FRONTEND_DIRECTORY='/srv/confidant-static'
```

### Development and testing settings

There's a few settings that are meant for development or testing purposes only
and should never be used in production:

```bash
# Disable all forms of authentication.
# NEVER USE THIS IN PRODUCTION!
export USE_AUTH=false
# Disable any use of at-rest encryption.
# NEVER USE THIS IN PRODUCTION!
export USE_ENCRYPTION=false
# Disable SSLify
# NEVER USE THIS IN PRODUCTION!
export SSLIFY=false
# Enable debug mode, which will also disable SSLify.
# NEVER USE THIS IN PRODUCTION!
export DEBUG=true
```

### Bootstrapping Confidant's own secrets

It's possible for confidant to load its own secrets from a KMS encrypted base64
encoded YAML dict. This dict can be generated (and decrypted) through a
confidant script:

```bash
cd /srv/confidant
source venv/bin/activate

# Encrypt the data
python manage.py generate_secrets_bootstrap --in unencrypted_dict.yaml --out encrypted_dict.yaml.enc
export SECRETS_BOOTSTRAP=`cat encrypted_dict.yaml.enc`

# Get a decrypted output of the yaml data
python manage.py decrypt_secrets_bootstrap
```

### Multi-account authentication

It's possible to use confidant across multiple AWS accounts by allowing
cross-account access to the AUTH\_KEY, but when you give access to the AUTH\_KEY
in other accounts, you're trusting the other account's IAM policy for
generating authentication tokens for services. Confidant supports scoping
services to accounts, where you generate a KMS key for each account, for
authentication. You can configure confidant to map keys to account names:

```bash
export SCOPED_AUTH_KEYS='{"sandbox-auth-key":"sandbox","primary-auth-key":"primary"}'
```

In the above example, if a user scopes a service to the "sandbox" account,
it'll require authentication to use the "sandbox-auth-key" KMS key.

### KMS authentication for end-users

In confidant version 1.1 we introduced a new version of KMS auth that allows
user authentication in addition to service authentication. By default confidant
will only allow service authentication.

```bash
# The alias of the KMS key being used for authentication that is specifically
# for the 'user' role. This should not be the same key as AUTH_KEY if your
# kms token version is less than 2, as it would allow services to masquerade
#  as users.
export USER_AUTH_KEY='user-auth-key'
# The maximum version of the authentication token accepted.
export KMS_MAXIMUM_TOKEN_VERSION='2'
# The minimum version of the authentication token accepted. You should set this
# as high as your clients support.
export KMS_MINIMUM_TOKEN_VERSION='1'
# Comma separated list of user types allowed to auth via KMS. Default is
# 'service'.
export KMS_AUTH_USER_TYPES='user,service'
```

### KMS grant management

By default confidant will manage KMS grants automatically for services that are
created, assuming that services are directly associated with IAM roles.
Confidant services don't need to be directly associated with IAM roles, though,
since access to the services is defined either by grants on the keys, or
through IAM policy. It's possible to disable confidant's grant management. If
you disable grant managenent, you'll either need to manage KMS key grants
manually, or you'll need to manage your IAM policy for KMS.

```bash
# Manage auth key grants for service to service authentication. Default True
export KMS_AUTH_MANAGE_GRANTS='False'
```

### User authentication session settings

By default (in confidant 1.1) confidant will use itsdangerous secure cookies
for session management, with a session lifetime and maximum session lifetime. A
user's session lifetime with automatically be extended any time a user performs
any action in the interface, but the user's session lifetime can only be
extended up to the maximum session lifetime, in which they'll be required to
login again. The session lifetime and maximum session lifetime can be adjusted:

```bash
# Session lifetime in seconds. Default is 12 hours.
export PERMANENT_SESSION_LIFETIME='43200'
# Maximum session lifetime in seconds. Default is 24 hours.
export MAX_PERMANENT_SESSION_LIFETIME='86400'
```

An alternative to using itsdangerous cookies is to store cookies in a redis
backend:

```bash
export REDIS_URL='redis://localhost:6381'
export PERMANENT_SESSION_LIFETIME='0'
```

### Confidant client configuration

Confidant exposes some data to its clients via a flask endpoint. It's possible
to expose additional custom data to clients through the server's configuration:

```bash
export CLIENT_CONFIG='{"blind_keys":{"us-east-1":"alias/blindkey-useast1","us-west-2":"alias/blindkey-uswest2"},"blind_cipher_type":"fernet","blind_cipher_version":"2","blind_store_credential_keys":true}'
```

The native client, or custom clients can use this data to help configure
themselves.

### Confidant performance settings

Confidant comes setup to perform well by default, but it's possible you may
find some of these settings too aggressive, or you may have enough clients or
services that the defaults aren't high enough.

The primary performance setting is for authentication token caching, and is set
to 4096. This should be set to something near your total number of clients with
unique authentication tokens. Assuming every client has a unique token, it
should be equal to greater than your number of clients. This cache avoids calls
to KMS for authentication, reducing latency and reducing likelyhood of
ratelimiting from KMS. The following configuration can adjust this:

```
export KMS_AUTH_TOKEN_CACHE_SIZE=4096
```

Confidant has a couple settings for tuning pynamodb performance. By default
confidant is pretty aggressive with pynamodb timeouts, setting the default
timeout to 1s. This is to fail fast and retry, rather than waiting on a blocked
request that could be general networking failures, attempting to avoid request
pileups. If this setting is too aggressive, you can adjust it via:

```
export PYNAMO_REQUEST_TIMEOUT_SECONDS=1
```

To avoid recreating connections to dynamodb on each request, we open a larger
than default number of pooled connections to dynamodb. Our default is 100. The
number of connections should be greater than or equal to the number of
concurrent requests per worker. To adjust this:

```
export PYNAMO_CONNECTION_POOL_SIZE=100
```

Similar to the performance tuning for dynamodb, we also have similar tuning
settings for KMS. For both connection and read timeouts, we aggressively set
the timeout to be 1s, since we assume any request that takes this long is
related to some network failure. To adjust these settings:

```
export KMS_CONNECTION_TIMEOUT=1
export KMS_READ_TIMEOUT=1
```

We also increase the default connection pool to KMS. This should be greater
than or equal to the number of concurrent requests per worker. To adjust this:

```
export KMS_MAX_POOL_CONNECTIONS=100
```

## KMS key policy configuration

Confidant needs to have special KMS key policy for both the at-rest
KMS\_MASTER\_KEY and the authentication AUTH\_KEY.

Here's an example key policy for the at-rest encryption key, KMS\_MASTER\_KEY, assuming the
above configuration. Note the following:

1. The "Enable IAM User Permissions" policy ensures that IAM users in your account
   that have the proper IAM permissions can manage this key. This is here to
   ensure you don't lock yourself out of the key.
1. The "Allow access for Key Administrators" policy ensures that a special IAM
   user can manage the KMS key.
1. The "Allow use of the key" policy ensures that confidant can use the key.

```json
{
  "Version" : "2012-10-17",
  "Id" : "key-consolepolicy-1",
  "Statement" : [ {
    "Sid" : "Enable IAM User Permissions",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:root"
    },
    "Action" : "kms:*",
    "Resource" : "*"
  }, {
    "Sid" : "Allow access for Key Administrators",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:user/myadminuser"
    },
    "Action" : [ "kms:Describe*", "kms:List*", "kms:Create*", "kms:Revoke*",
"kms:Enable*", "kms:Get*", "kms:Disable*", "kms:Delete*", "kms:Put*",
"kms:Update*" ],
    "Resource" : "*"
  }, {
    "Sid" : "Allow use of the key",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:role/confidant-production"
    },
    "Action" : [ "kms:Decrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*",
"kms:DescribeKey", "kms:Encrypt" ],
    "Resource" : "*"
  } ]
}
```

Here's an example key policy for the authentication key, AUTH\_KEY, assuming the
above configuration. Note the following:

1. The "Enable IAM User Permissions" policy ensures that IAM users in your account
   that have the proper IAM permissions can manage this key. This is here to
   ensure you don't lock yourself out of the key.
1. The "Allow access for Key Administrators" policy ensures that a special IAM
   user can manage the KMS key.
1. The "Allow use of the key" policy ensures that confidant can use the key.
1. The "Allow attachment of persistent resources" policy ensures that confidant
   can add and revoke grants for the auth key, which is necessary to give
   access to context specific encrypt and decrypt calls for service IAM roles.


```json
{
  "Version" : "2012-10-17",
  "Id" : "key-consolepolicy-1",
  "Statement" : [ {
    "Sid" : "Enable IAM User Permissions",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:root"
    },
    "Action" : "kms:*",
    "Resource" : "*"
  }, {
    "Sid" : "Allow access for Key Administrators",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:user/myadminuser"
    },
    "Action" : [ "kms:Describe*", "kms:List*", "kms:Create*", "kms:Revoke*",
"kms:Enable*", "kms:Get*", "kms:Disable*", "kms:Delete*", "kms:Put*",
"kms:Update*" ],
    "Resource" : "*"
  }, {
    "Sid" : "Allow use of the key",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:role/confidant-production"
    },
    "Action" : [ "kms:Decrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*",
"kms:DescribeKey", "kms:Encrypt" ],
    "Resource" : "*"
  }, {
    "Sid" : "Allow attachment of persistent resources",
    "Effect" : "Allow",
    "Principal" : {
      "AWS" : "arn:aws:iam::12345:role/confidant-production"
    },
    "Action" : [ "kms:ListGrants", "kms:CreateGrant", "kms:RevokeGrant" ],
    "Resource" : "*"
  } ]
}
```

## Confidant IAM role configuration

Confidant needs some IAM policies to properly function. Here's some example
policies, based on the above configuration:

A policy to find instance profiles, so that Confidant can know which IAM roles
exist. This is to make it easier for users to find which services they can
create.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "iam:ListRoles",
                "iam:GetRole"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
```

Allow Confidant to generate random data from KMS:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "kms:GenerateRandom"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}
```

Allow Confidant access to its DynamoDB table. We restrict DeleteTable access,
because the application should never be able to do that.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "dynamodb:*"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:dynamodb:*:*:table/confidant-production",
                "arn:aws:dynamodb:*:*:table/confidant-production/*"
            ]
        },
        {
            "Action": [
                "dynamodb:DeleteTable"
            ],
            "Effect": "Deny",
            "Resource": [
                "arn:aws:dynamodb:*:*:table/confidant-production"
            ]
        }
    ]
}
```

## Confidant DynamoDB table configuration

You'll need to create a dynamodb with two global indexes:

```
hash id: id
hash key data type: S

global indexes:

data_type_date_index:
  hash key: data_type
  hash key data type: S
  range key: modified_date
  range key data type: S

data_type_revision_index:
  hash key: data_type
  hash key data type: S
  range key: revision
  range key data type: N
```

Provisioned read/write units can be relative low on both the primary table and
the indexes. See your usage in cloudwatch and increase throughput as necessary.
