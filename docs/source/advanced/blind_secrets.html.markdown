---
title: Server-blinded credentials
---

# Server-blinded secrets

## What are server-blinded secrets?

Some secrets are so sensitive that even if your confidant server is breached,
it shouldn't give the attacker access to the secret. With confidant's plain
secrets, confidant stores the secrets encrypted at rest, and encrypts and
decrypts secrets on behalf of services. Starting in confidant version 1.1, it's
possible to use another type of secret: server-blinded secrets. Server-blinded
secrets are more difficult to use, and there's a lot more thought that needs to
go into multi-region and multi-account planning when using server-blinded
secrets, so it's important to have a good plan in place before using them.

The basic idea behind server-blinded secrets is that rather than having
confidant handle the enryption and decryption of the secrets, end-users will
encrypt the secrets prior to them being sent to confidant, and your services
will decrypt the secrets when they receive them.

The new confidant client in version 1.1 has support for server-blinded secrets.
Like secrets in confidant are referred to as credentials, blinded secrets are
referred to as blind credentials.

## KMS keys and IAM policy examples for server-blinded secrets

It's necessary to create a new KMS key in each region you wish to support. As
an example, we'll name our new KMS keys confidant-production-useast1-blind and
confidant-production-uswest2-blind. Though it's possible to use KMS key policy
or key grants to manage access to this key, it's much easier to manage access
to the key through IAM user and role policies. A reason why this is easier is
because it gives you fine-grained access controls at the level of your service,
rather than in a centralized location. First let's allow users to use the blind
keys to encrypt data:

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
                "arn:aws:kms:us-east-1:12345:key/your-east-blind-key-id",
                "arn:aws:kms:us-west-2:12345:key/your-west-blind-key-id'
            ],
            "Condition": {
                "Bool": {
                    "aws:MultiFactorAuthPresent": "true"
                }
            }
        }
    ]
}
```

The above policy allows users to encrypt data using the key. It doesn't have
any restrictions to the encryption context, so that users can set custom
contexts that can be used to restrict access on the service side.

Next let's create an IAM policy for an IAM role 'serviceA-production' that's
attached to our serviceA-production-useast1 and serviceA-production-uswest2
autoscale groups:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "kms:Decrypt"
            ],
            "Effect": "Allow",
            "Resource": [
                "arn:aws:kms:us-east-1:12345:key/your-east-blind-key-id",
                "arn:aws:kms:us-west-2:12345:key/your-west-blind-key-id'
            ],
            "Condition": {
                "StringEquals": {
                    "kms:EncryptionContext:group": "serviceA-production"
                }
            }
        }
    ]
}
```

This policy allows the IAM role to decrypt anything using the blind keys in
us-east-1 or us-west-2, if the encryption context has a 'group' key with a
'serviceA-production' value. The confidant client has an option for using group
as the context, which makes it a bit easier to use; so, though you're not
required to use 'group' for the context, you may want to.

### Creating and updating server-blinded secrets using the confidant client

Before we get started, you should read the documentation about installing and
configuring the confidant client, if you haven't yet.

To create a blind secret, we'll call confidant with the 'create_blind_credential'
argument. Like normal secrets, you're required to give the secret a name and to
give it a dict of credential pairs, but you must also provide the group
context, and a set of blind keys that it can use. Here's an example:

```bash
confidant create_blind_credential --mfa --name "test blind secret" \
    --credential-pairs '{"api_public_key":"12345","api_private_key":"abcde"}' \
    --group-context '{"group":"serviceA-production"}' --blind-keys \
    '{"us-east-1":"alias/confidant-production-useast1-blind","us-west-2":"alias/confidant-production-uswest2-blind"}'
```

Note in the above that the context we're using a group context that matches the
IAM policy we've added to the service's IAM role. Also, for the blind keys,
we're telling the confidant client which keys it should use in each region.

When the blind secret is created, it'll output a json document describing the
new secret. An attribute returned is id, which you'll need to update secrets.
You can also view blind secrets through the web interface to find the secret's
ID. The web interface will show the encrypted contents of the credential pairs,
but it can't show the unencrypted contexts.

To update secrets, you pass in the id of the secret and the attributes you'd like
to change; If you're updating the credential pairs, it's necessary to also pass
in the group context and the blind keys. Here's an example:

```bash
confidant update_blind_credential --mfa --id dd329c9174924a0a9bf8bf3e7fbdaef9 \
    --credential-pairs '{"api_public_key":"67890","api_private_key":"fghij"}' \
    --group-context '{"group":"serviceA-production"}' --blind-keys \
    '{"us-east-1":"alias/confidant-production-useast1-blind","us-west-2":"alias/confidant-production-uswest2-blind"}'
```

Like the creation subcommand, update_blind_credential will output a json
document describing the updated secret.

If you've given users IAM privileges to decrypt blind secrets, they can also
view the decrypted versions of blind secrets using the get_blind_credential
subcommand. Notice that by default this subcommand will return the encrypted
version of the credential pairs, unless --decrypt-blind is used:

```bash
confidant get_blind_credential --mfa --id dd329c9174924a0a9bf8bf3e7fbdaef9 \
    --decrypt-blind
```
