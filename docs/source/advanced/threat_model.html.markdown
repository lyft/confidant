---
title: Threat model
---

# Threat model

The threat model is written in terms of what an attacker can accomplish from
various perspectives. It's meant to be exhaustive, and anything missing should
be reported as an issue in the github project.

## Web client threat model

### Assumptions

1. Valid authenticated and authorized users act in good faith.
1. Users' computers are not infected by malware.
1. TLS is being used for http connections and is configured in a secure manner.

### What an authenticated user can achieve

1. A user can view all secrets.
1. A user can view all secret to service mappings.
1. A user can create new revisions of a secret.
1. A user can create new revisions of a service mapping.

### What compromise of an authenticated user's computer can achieve

1. Compromise of a user's computer can give the attacker access to all actions
   achievable by the authenticated user.

### What an unauthenticated local network attacker who can observe network traffic can achieve

1. The passive attacker can learn which client IP addresses are using Confidant.
1. The passive attacker can block access to Confidant.
1. The passive attacker can observe the approximate size of secrets.

### What an unauthenticated attacker from the Internet can achieve

Note: It's highly suggested to run Confidant on a private network or VPN,
rather than directly accessible on the internet.

1. An attacker from the internet can DoS the Confidant server.

## Web server threat model

### Assumptions

1. The web service is given the least amount of AWS IAM privilege allowed to
   run properly, as defined in the configuration guide.
1. The web service is given only the network access necessary to run properly.

### What an attacker can achieve through compromise of the Confidant web server

1. An attacker who successfully compromises the Confidant flask server has full
   control of the service's IAM credentials and can read all secrets, corrupt or
   delete secrets, remap secrets to other services, manipulate web server logs,
   and modify KMS AUTH\_KEY grants.

## Service client threat model

### Assumptions

1. IAM policy is properly configured for the KMS AUTH\_KEY, if using KMS auth.
1. IAM policy is properly configured for the S3 locations, if S3 auth is used.
1. TLS with a valid trust is being used for http connections.
1. IAM policy is properly configured for DynamoDB

### What the service can achieve

1. A service can retrieve the unencrypted secrets mapped to it.

### What an attacker can achieve with a filesystem read vulnerability

Client management and storage of secrets is an implementation detail outside of
the scope of the Confidant service itself, but the following threat models
could apply.

1. If a service is storing the authentication token on the filesystem, an
   attacker would be able to steal the token, which would give them the access
   level of the service for the lifetime of the token.
1. If a service is storing the secrets on the filesystem unencrypted, an
   attacker would be able to steal the service secrets.

## Storage threat model

### Assumptions

1. cryptography.io's Fernet implementation is secure.
1. KMS's AES implementation is secure.
1. Attackers don't have access to the KMS master key.

### What an attacker with DynamoDB access can achieve

1. An attacker with full DynamoDB access can delete or corrupt all service and
   secrets.
1. An attacker with full DynamoDB access could map secrets to other services.
1. An attacker with read DynamoDB access can read service mapping data and
   the metadata (friendly name, modified date, modified by, etc.) of secrets.
