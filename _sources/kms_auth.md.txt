# KMS authentication

## Service-to-service authentication

When a service is created in Confidant, Confidant, by default, will generate a
couple of grants on the AUTH\_KEY KMS key. One grant allows the service to do
encryptions or decryptions using the key, as long as the 'from' encryption context
is the name of the service and the 'user\_type' is 'service'; the other grant allows
the service to do decryptions using the key, as long as the 'to' encryption context
is the name of the service. This is what enables the services to get their secrets
from Confidant.

This guide is mostly going to be a crash-course on how KMS works, since we're
just leveraging it for authentication. If you're not very familiar with KMS,
you may want to take a look at the following docs:

* http://docs.aws.amazon.com/kms/latest/developerguide/concepts.html
* http://docs.aws.amazon.com/kms/latest/developerguide/crypto-intro.html
* http://docs.aws.amazon.com/kms/latest/developerguide/crypto_authen.html
* http://docs.aws.amazon.com/kms/latest/developerguide/encrypt-context.html
* http://docs.aws.amazon.com/kms/latest/developerguide/crypto-terminology.html
* http://docs.aws.amazon.com/kms/latest/developerguide/grants.html

Let's take a quick look at a basic example using boto3:

```python
>>> import boto3
>>> import datetime
>>>
>>> now = datetime.datetime.now()
>>> not_after = now + datetime.timedelta(minutes=60)
>>> not_before = now.strftime("%Y%m%dT%H%M%SZ")
>>> not_after = not_after.strftime("%Y%m%dT%H%M%SZ")
>>>
>>> kms = boto3.client('kms')
>>> plaintext = '{"not_before": "{0}", "not_after": "{1}"}'.format(not_before, not_after)
>>> token = kms.encrypt(
>>>     KeyId='alias/authnz-testing', Plaintext=plaintext,
>>>     EncryptionContext={
>>>         'from': 'myservice-production',
>>>         'to': 'confidant-production',
>>>         'user_type': 'service'
>>>     }
>>> )
>>>
>>> token
{u'KeyId': u'arn:aws:kms:us-east-1:12345:key/abcdefgh-1234-5678-9abcd-ee72ac95ae8c',
'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId':
'3a48f2ad-072d-11e5-88fb-17df9ce1a01a'}, u'CiphertextBlob': '\n
\x999\x9e$yO\x92\x1dg\xbbZ^S\x84\xdaI\xbf\x14@\x81\x8a\x1c\xf2\xf8Z\x05\xed\xed\xb2\x8d)T\x12\x8f\x01\x01\x01\x02\x00x\x999\x9e$yO\x92\x1dg\xbbZ^S\x84\xdaI\xbf\x14@\x81\x8a\x1c\xf2\xf8Z\x05\xed\xed\xb2\x8d)T\x00\x00\x00f0d\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0W0U\x02\x01\x000P\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xd3\x96\x0c\x91\x83\xd2l!\xfb\xa6\xc2\x90\x02\x01\x10\x80#\x97Z\xd1\xbb\xb4_\x12\xea\x1a\xed\x85\x0e\x9b1\xfa0j\xca1(\xc7\xc3\x8czT\xd4\x8fk\x08\x00\xa8\xcd\xe5\x82\xb3'}
>>>
>>> kms.decrypt(
>>>     CiphertextBlob=token['CiphertextBlob'],
>>>     EncryptionContext={
>>>         'from': 'myservice-production',
>>>         'to': 'confidant-production',
>>>         'user_type': 'service'
>>>     }
>>> )
{u'Plaintext': '{"not_before": "20150914T172347Z", "not_after": "20150914T182347Z"}', u'KeyId':
u'arn:aws:kms:us-east-1:12345:key/abcdefgh-1234-5678-9abcd-ee72ac95ae8c',
'ResponseMetadata': {'HTTPStatusCode': 200, 'RequestId':
'6450392b-072d-11e5-87df-5345698b39e1'}}
```

Notice that we could encrypt something and then decrypt it, as long as we
passed in the same context.

Now let's change the encryption context slightly:

```python
>>> kms.decrypt(
>>>     CiphertextBlob=token['CiphertextBlob'],
>>>     EncryptionContext={
>>>         'from': 'notmyservice-production',
>>>         'to': 'confidant-production',
>>>         'user_type': 'service'
>>>     }
>>> )
Traceback (most recent call last):
  File "<stdin>", line 1, in <module>
  File "/home/rlane/Envs/boto3/lib/python2.7/site-packages/botocore/client.py",
line 249, in _api_call
    raise ClientError(parsed_response, operation_name)
botocore.exceptions.ClientError: An error occurred (InvalidCiphertextException)
when calling the Decrypt operation: None
```

Note that there's a couple reasons this would fail:

1. The 'from' context passed into this decryption action doesn't match the 'from'
   context that was used during the encryption action.
1. This service isn't allowed to do a decryption action with the provided
   'from' context, since the grant is limiting the 'from' context to
   'myservice-production'.

Let's take a look at how to implement an authentication flow using this on the
server and the client. Here's the server side (using flask):

```python
def get_key_arn():
    # You should cache this.
    key = kms.describe_key(
        KeyId='alias/{0}'.format(app.config['MASTER_KEY_ID'])
    )
    return key['KeyMetadata']['Arn']

def _parse_username(username):
    username_arr = username.split('/')
    if len(username_arr) == 3:
        # V2 token format: version/service/myservice or version/user/myuser
        version = int(username_arr[0])
        user_type = username_arr[1]
        username = username_arr[2]
    elif len(username_arr) == 1:
        # Old format, specific to services: myservice
        version = 1
        username = username_arr[0]
        user_type = 'service'
    else:
        raise TokenVersionError('Unsupported username format.')
    return version, user_type, username

def decrypt_token(token, username):
    version, user_type, _username = _parse_username(username)
    try:
        token = base64.b64decode(token)
        data = kms.decrypt(
            CiphertextBlob=token,
            EncryptionContext={
                # This token is sent to us.
                'to': app.config['IAM_ROLE'],
                # From another service.
                'from': _username,
                'user_type': user_type
            }
        )
        # Decrypt doesn't take KeyId as an argument. We need to verify the
        # correct key was used to do the decryption.
        # Annoyingly, the KeyId from the data is actually an arn.
        key_arn = data['KeyId']
        if key_arn != get_key_arn():
            raise TokenDecryptError('Authentication error.')
        payload = json.loads(data['Plaintext'])
    # We don't care which exception is thrown. If anything fails, we fail.
    except Exception:
        raise TokenDecryptError('Authentication error.')
    time_format = "%Y%m%dT%H%M%SZ"
    now = datetime.datetime.utcnow()
    try:
        not_before = datetime.datetime.strptime(payload.get('not_before'), time_format)
        not_after = datetime.datetime.strptime(payload.get('not_after'), time_format)
    except Exception:
        raise TokenDecryptError('Authentication error.')
    # Ensure the token is within the validity window.
    if (now < not_before) or (now > not_after):
        raise TokenDecryptError('Authentication error.')
    return payload


def require_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        try:
            payload = keymanager.decrypt_token(
                request.headers['X-Auth-Token'],
                request.headers['X-Auth-From']
            )
            # We could do additional checks here, based on the payload
            # contents, like check for scope passed in.
            return f(*args, **kwargs)
        except TokenDecryptError:
            return abort(401)
        # Paranoia
        return abort(401)
    return decorated
```

And here's the client side (using requests):

```python
import datetime
import boto3
import base64
import requests

now = datetime.datetime.utcnow()
not_after = now + datetime.timedelta(minutes=60)
not_before = now.strftime("%Y%m%dT%H%M%SZ")
not_after = not_after.strftime("%Y%m%dT%H%M%SZ")
auth_context = {
    'from': 'servicea-development',
    'to': 'serviceb-development',
    'user_type': 'service'
}
plaintext = '{"not_before": "{0}", "not_after": "{1}"}'.format(not_before, not_after)
kms = boto3.client('kms')
token = kms.encrypt(
    KeyId='alias/authnz-testing',
    Plaintext=plaintext,
    EncryptionContext=auth_context
)['CiphertextBlob']
token = base64.b64encode(token)
headers = {
    'X-Auth-Token': token,
    # version: 2, user_type: service, username (2/service/username)
    'X-Auth-From': '2/service/{1}'.format(auth_context['from'])
}
response = requests.get('/v1/services/servicea-development', headers=headers)
```

This is almost exactly the server and client auth flow used in Confidant. This
same pattern can be applied for doing your own service-to-service
authentication as well.

Something to notice here is that we're doing extra work based on the payload
contents of the token. We're adding `not_before` and `not_after` data so that we can
give this token a lifetime. The client is specifying the lifetime of the token
itself. You could put additional information into the payload, such as token
scope, additional contraints, etc.. In Confidant, on the server side we also
limit the maximum lifetime of a token, to ensure clients are occasionally
rotating their authentication tokens.

### IAM policy configuration for service-to-service auth

If you wish to disable grant management for KMS auth, it's possible to manage
IAM policy for service-to-service authentication. An assumption of this example
is that a confidant service (serviceA-production) maps directly to an IAM role
(serviceA-production) and your confidant service is confidant-production. Let's
add a policy to the service, to allow authentication:

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
        },
        {
            "Action": [
                "kms:Encrypt"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:kms:us-east-1:12345:key/your-authnz-key-id"
            ],
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:to": "confidant-production",
                    "kms:EncryptionContext:user_type": "service",
                    "kms:EncryptionContext:from": "serviceA-production"
                }
            }
        }
    ]
}
```

## Passing encrypted data between services

In the service-to-service section we actually passed encrypted
content between two services; however, we used KMS's Encrypt action
directly, which is limited to 4 KB of data. If all you need to do is pass
messages smaller than 4KB, this will work perfectly for you. If you need to
pass more than 4KB, you'll need to generate data keys, and do a bit of
encryption yourself, using the data key.

Confidant does this using the cryptography.io Python library and its Fernet
implementation. It doesn't matter which language or library you use, the steps
are basically the same:

1. Generate a data key, with context: {'from': 'servicea-production', 'to':
   'serviceb-production', 'user_type': 'service'}
1. Use the Plaintext portion the data key to encrypt your data.
1. Pass the CiphertextBlob portion of the data key along with the data to the
   other service.
1. The other service should decrypt the CiphertextBlob portion of the data key,
   giving it the Plaintext portion.
1. The other service will use the Plaintext portion of the data key to decrypt
   the data.

## User-to-service authentication

Confidant does not setup grants for user authentication. To enable user to service
KMS authentication, it's necessary to setup IAM policy for your KMS keys. Thankfully,
the IAM policy for this is pretty straightforward:

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
        },
        {
            "Action": [
                "kms:Encrypt"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:kms:us-east-1:12345:key/your-authnz-key-id"
            ],
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:to": "confidant-production",
                    "kms:EncryptionContext:user_type": "user",
                    "kms:EncryptionContext:from": "${aws:username}"
                },
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```

This policy allows a user to generate KMS authentication tokens, as long as the
'from' context matches their IAM user name, the 'to' context is to 'confidant-production'
and the 'user_type' is 'user'. Note that if you wanted to allow authentication from users
to any service, you can change the second statement slightly:

```json
        {
            "Action": [
                "kms:Encrypt"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:kms:us-east-1:12345:key/your-authnz-key-id"
            ],
            "Condition": {
                "StringLike": {
                    "kms:EncryptionContext:to": "*",
                },
                "StringEquals": {
                    "kms:EncryptionContext:user_type": "user",
                    "kms:EncryptionContext:from": "${aws:username}"
                },
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
```

When the user authenticates, they'll use a header like: `'X-Auth-From': '2/user/rlane'`.
From the server side, you'll be able to verify the token, then you can mark the user
by user_type, so that you can do access control based on their type (service or user).

## Multi-account KMS authentication

Without much change it's possible to do KMS authentication across accounts. In
the simplest approach, you can simply allow multiple accounts to use the KMS
authnz key. The downside to this is that when you allow another account to use
the KMS key, you're trusting that account with the IAM policy of whichever
actions you're allowing. So, if you have two accounts: sandbox and production,
and you allow sandbox to use the KMS authnz key in production, sandbox can
write IAM policies that allow it to generate tokens for any service in
confidant, which may not be what you intend.

Starting in version 1.1, Confidant added support for using scoped KMS
authentication keys. Rather than using a single KMS authentication key for all
accounts, you'll create a KMS key for each account. The key policy for each key
will allow its specific account to use the key. Note that it's important that
all of these keys live in the same AWS account as the confidant service.

After creating and configuring the keys, you can use the SCOPED_AUTH_KEYS
setting in confidant to map key aliases to friendly account names. Once this is
configured, users can scope services to accounts.

If you're implementing KMS auth outside of confidant: we map keys to account
names. When a token is decrypted, part of what KMS returns is the key ARN used
for the decryption. We take that ARN and lookup the alias that's associated with
it. We take the alias and look it up in the SCOPED_AUTH_KEYS mapping to find its
associated account. If the scoped service matches the key used, we accept the
request.
