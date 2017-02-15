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

To enable SAML authentication, set the `USER_AUTH_MODULE` environment variable.

```bash
# The authentication type we'll be using for user authentication - set to SAML.
export USER_AUTH_MODULE='saml'
```

You will first need to create a SAML application in your Identity Provider
(IdP) and provide the following details to it:

* ACS URL: https://your-confidant-url-here.com/v1/saml/consume
* Entity ID: https://your-confidant-url-here.com/v1/saml/consume

You can optionally include an attribute mapping on the (IdP) to pass the first
name as `first_name` and last name as `last_name` to the service provider (SP)
so that this information is captured when logging in to Confidant. The IdP
should provide some details about the Entity ID, the IdP certificate, the
Sign-On URL and the Log-Out URL (the Log-Out URL may not be provided depending
on the IdP). Export your SAML details as environment variables for Confidant to
read:

```bash
# Root URL that browsers use to hit Confidant.
export SAML_CONFIDANT_URL_ROOT='https://your-confidant-url-here.com'
# SAML IdP Entity ID (typically a URL)
export SAML_IDP_ENTITY_ID='https://idp-provided-url-here.com/'
# SAML IdP Single Sign On URL (HTTP-REDIRECT binding only)
export SAML_IDP_SIGNON_URL='https://idp-provided-url-here.com/'
# SAML IdP Single Logout URL, optional, only if IDP supports it
# (HTTP-REDIRECT binding only)
export SAML_IDP_LOGOUT_URL='https://idp-provided-url-here.com/'
# SAML IdP X.509 certificate in PEM format
export SAML_IDP_CERT="-----BEGIN CERTIFICATE-----
MIICsDCCAhmgAwIBAgIJALw1z/rM2pg2MA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwMjE1MTk0NjAyWhcNMjcwMjE1MTk0NjAyWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDVlwBwiK9S9uQo0uNT1ho0TzfPSQ3MZ0QNS7MAUSBUWwqx7B8orjmzohSliWjC
0vlb14F8bqkJpcpMEZRrG4AM2H41XG2T/aCBjH4w3SUHZzTsCxuC1VUym4sLbWBU
DtvApkpEJDnQiYyQH4M3KMFqKzEB/cu1YEKcDsXqUjHKMQIDAQABo4GnMIGkMB0G
A1UdDgQWBBT4HpgZAnlydQzcbhE7xPB9zendbDB1BgNVHSMEbjBsgBT4HpgZAnly
dQzcbhE7xPB9zendbKFJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUt
U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJALw1z/rM
2pg2MAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAirAqPWuc7zX/Qc7Q
6xbYd/NdCLIVXoQoPbnNDGuv25b1PZKYcfEuGBt+2kU7Xo0AAxgFUEQ00juyBg/r
616V3SRuXi0r+xbUOdTvEz7visAXu2e3kyDQncvryEhq3DCffc4UTGbpZrnTxhRm
1DJr81eyo8/xREBnRcK5/DCj+U4=
-----END CERTIFICATE-----"
# SAML IdP X.509 certificate file in PEM format
export SAML_IDP_CERT_FILE='/path/to/idp_cert.pem'
# NOTE: Only provide either SAML_IDP_CERT or SAML_IDP_CERT_FILE (you should not
# provide both).
```

If your IdP requires you to sign your SAML requests, you will need to set up
the service provider (SP) details. If you do not already have a certificate
and private key for the SP, you can generate one using the command below:

```bash
# Generate a self-signed certificate and place the certificate in
# sp.crt and the private key in private.key. It will ask for input for a
# passphrase.
openssl req -new -x509 -days 365 -out sp.crt -keyout private.key
```

Export the SP details as environment variables for Confidant to read:

```bash
# Raw X.509 certificate in PEM format
export SAML_SP_CERT="-----BEGIN CERTIFICATE-----
MIICsDCCAhmgAwIBAgIJAKTiHVFA9kAbMA0GCSqGSIb3DQEBBQUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIEwpTb21lLVN0YXRlMSEwHwYDVQQKExhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTcwMjE1MjIyODQzWhcNMTgwMjE1MjIyODQzWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECBMKU29tZS1TdGF0ZTEhMB8GA1UEChMYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQDF4sRC8SXwhYB6al8UhGjeAB6xJXYnjFEqhd8U3Kc1Gs9SyxDsId4tOHYotWdK
C3doeLbCuM0xqVbWZX8XUptLR1PImZvUX2KmLOtO0NVIGGa17XlUJBcgd9uKLrCO
lizS8saWTLuPdNdlv7WNYyGSRAgw9/H06Szy2b7735thiQIDAQABo4GnMIGkMB0G
A1UdDgQWBBQW3mpcpfpspIF4pKleytfm3gP6bzB1BgNVHSMEbjBsgBQW3mpcpfps
pIF4pKleytfm3gP6b6FJpEcwRTELMAkGA1UEBhMCQVUxEzARBgNVBAgTClNvbWUt
U3RhdGUxITAfBgNVBAoTGEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZIIJAKTiHVFA
9kAbMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEFBQADgYEAi4fOkax7ZMKw9wbF
Do1A1c8YXmPERHtfNuGJb3QINLqeMXl+4p/ryzTJR0UP6iqDTPOq02mtJ+eR4AhC
Fmgrm671fKCTYu3vjQS33IXOoGW+0f2XX+gWVHie8ZC4vi/dfh30At+A6wJelXkz
cRNGXl5zn4uyC6T8g1rC544tbb8=
-----END CERTIFICATE-----"
# Path to SP X.509 certificate file in PEM format
export SAML_SP_CERT_FILE='/path/to/sp_cert.pem'
# NOTE: Only provide either SAML_SP_CERT or SAML_SP_CERT_FILE (you should not
# provide both).

# Path to SP private key file in PEM format
export SAML_SP_KEY_FILE='/path/to/sp_key.key'
# Raw SP private key in PEM format
# This setting can be loaded from the SECRETS_BOOTSTRAP.
export SAML_SP_KEY="-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: DES-EDE3-CBC,241900635D644CE6

RcUZgdpnT2ZUdMGoKb2+3TbenSuT/dsi3SRajCL6IvbFOG9wUo4TvIcH0CCZB5ZY
u08B/zmuOpm5QDEFbfiipqs76SXHKUZssKrEiiJPI5FZKfkyCkK5vV7eLhuI/B5U
f0S6MBXXvP1dUg5LzZPOhNfJVcaNxOCFPBgl6HJ6sn0qkLOzrcc4wHycHsJmDxhe
SC8EfIWv94vk8EsW/pWRsc+AQ1HPw3SHEPMGv6ojUdGPlF136ZTNSTjUlygHjhPX
nes9+PKgt+Rfpb+kolXSGlvujFsWTxGz9h08X37RhyVGV8V9bS6REt62OGdErofp
BSRO3791dOhYcEywDt8oaFaieR3ND+iL4RnsfKseQRM+EAUBhjVjxqP64h5DlaNc
UHzaBuCWUeGoorzVqSG+UotcWYaXeyq+WjkCaDFPI/sCpk0goJtUjzJZP3nL1vKy
BMfDyjrz3QPkLU7hksWH4G89H2NXGGSvHttzzY3ihYqVXVJiNASCXPqo3qjnO+/Z
Qsis6z//zd/URtqmk2pr6RznqJJg74NL4wj8pMHRlJ3Li7LDYm6q6GCmQugIZ+4l
M1nlyELLrq4fRellVmXXA+z0FGqDxEe2q8g4KBbdjpFCzYO0kgqbNiFNilx3SAZY
B5FP+dxNU+ZkA1mkS6u2j/sRpdDvPMJJ9R0xdUmrJODwdVL+B2jvfhLsTmNuOnzF
hBK/zw00MXYq37qv7x3JcdCrUAtEhinXbdx3xmBPshGHy6YYH5L4UPkrxlV7yAmg
Uiql+YCDH79JiVLf8jvKJa3WDPeTEPBEmZDjpdefimdswU73J+oPmg==
-----END RSA PRIVATE KEY-----"
# Password for the SAML_SP_KEY_FILE
# This setting can be loaded from the SECRETS_BOOTSTRAP.
export SAML_SP_KEY_FILE_PASSWORD='verysecurepassword'
```

There are some other SAML options that you can set that may need to be changed
depending on the IdP that you use. If you get SAML errors, tweaking these
variables may help solve your issue. The values listed below are the defaults
that Confidant uses.

```bash
# Algorithm used for SAML signing
# default: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256
# see also: http://www.w3.org/2000/09/xmldsig#rsa-sha1
export SAML_SECURITY_SIG_ALGO='http://www.w3.org/2001/04/xmldsig-more#rsa-sha256'
# Whether to require signatures on SLO responses
export SAML_SECURITY_SLO_RESP_SIGNED=true
# Whether to require signatures on full SAML response messages
export SAML_SECURITY_MESSAGES_SIGNED=true
# Whether to require signatures on individual SAML response assertion fields
export SAML_SECURITY_ASSERTIONS_SIGNED=false
# NOTE: You will very likely want at least one of
# SAML_SECURITY_MESSAGES_SIGNED or SAML_SECURITY_ASSERTIONS_SIGNED to be true.
# Whether you want an attribute statement from the SAML assertion
export SAML_WANT_ATTRIBUTE_STATEMENT=true
```

To debug SAML and/or test SAML in development, you may want to set either of
the following flags to true.

```bash
# Debug mode for python-saml library. Follows global DEBUG setting if not set.
export SAML_DEBUG=false
# Pretend that all requests are HTTPS for purposes of SAML validation. This is
# useful if your app is behind a weird load balancer and flask isn't respecting
# X-Forwarded-Proto. For security, this flag will only be respected in debug
# mode.
export SAML_FAKE_HTTPS=false
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

It's possible to use custom cookie names for both the session cookie, and for
the XSRF token cookie:

```bash
export SESSION_COOKIE_NAME='confidant_session'
export XSRF_COOKIE_NAME='XSRF-TOKEN'
```

### Disabling credential conflict checks

By default confidant will ensure that credentials mapped to a service don't
have any conflicting credential pair keys. These checks occur when mapping
credentials to a service, or when modifying credentials that are mapped to a
service. To disable this check:

```bash
export IGNORE_CONFLICTS='True'
```

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
