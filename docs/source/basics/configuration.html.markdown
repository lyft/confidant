---
title: Configuration
---

# Configuration

Confidant is primarily configured through environment variables. The list of
all available configuration options can be found in the settings.py file.

Assuptions, from the prerequisites guide:

1. Your Google application is setup and you know your client id and secret key.
1. Your KMS auth and encryption keys are created.
1. Your DynamoDB table has been created.

## Basic environment configuration

This is the minimum configuration needed to use Confidant:

```bash
# The region our service is running in.
export AWS_DEFAULT_REGION='us-east-1'
# The IAM role name of the confidant server.
export AUTH_CONTEXT='confidant-production'
# The KMS key used for auth.
export AUTH_KEY='authnz-production'
# A long randomly generated string used for the google OAuth2 flow.
export AUTHOMATIC_SALT='H39bfLCqLbrYrFyiJIxkK0uf12rlzvgjgo9FqOnttPXIdAAuyQ'
# The DynamoDB table name for storage.
export DYNAMODB_TABLE='confidant-production'
# Set the gevent resolver to ares; see:
#   https://github.com/surfly/gevent/issues/468
export GEVENT_RESOLVER='ares'
# The client id and consumer secret from the google developer console.
export GOOGLE_OAUTH_CLIENT_ID='123456789-abcdefghijklmnop.apps.googleusercontent.com'
export GOOGLE_OAUTH_CONSUMER_SECRET='123456789abcdefghijklmnop'
# The KMS key used for at-rest encryption in DynamoDB.
export KMS_MASTER_KEY='confidant-production'
# The Redis server used for sessions.
export REDIS_URL='redis://localhost:6381'
# A long randomly generated string for CSRF protection.
export SESSION_SECRET='aBVmJA3zv6zWGjrYto135hkdox6mW2kOu7UaXIHK8ztJvT8w5O'
```

## Advanced environment configuration

Confidant can track some stats via statsd. By default it's set to send stats to
statsd on localhost on port 8125.

```bash
export STATSD_HOST='mystatshost.example.com'
export STATSD_PORT='8125'
```

Confidant can also send graphite events on secret updates or changes in service
mappings:

```bash
export GRAPHITE_EVENT_URL='https://graphite.example.com/events/'
export GRAPHITE_USERNAME='mygraphiteuser'
export GRAPHITE_PASSWORD='mylongandsupersecuregraphitepassword'
```

It's possible to restrict access to a subset of users that authenticate
using Google authentication:

```bash
export USERS_FILE='/etc/confidant/users.yaml'
export GOOGLE_AUTH_EMAIL_SUFFIX='@example.com'
```

In the above configuration, Confidant will limit authentication to users with
the email domain @example.com. Additionally, Confidant will look in the
users.yaml file for a list of email addresses allowed to access Confidant.

It's possible to customize portions of the angularjs application as well.
Currently you can add a documentation section to the credential details view.
We'd like to make more customization available. Please open a github issue with
specific customizations you'd like focused on first. The custom js/css/html
will be served from a directory you specify:

```bash
export CUSTOM_FRONTEND_DIRECTORY='/srv/confidant-static'
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
"kms:DescribeKey", "kms:Encrypt", "kms:GenerateRandom" ],
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
"kms:DescribeKey", "kms:Encrypt", "kms:GenerateRandom" ],
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
                "iam:GetInstanceProfile",
                "iam:ListInstanceProfiles"
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
