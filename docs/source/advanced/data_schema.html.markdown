---
title: Data Schema
---

# DynamoDB Data Schema

We define __credential__, __archive-credential__, __service__, and
__archive_service__. __credential__ and __service__ are the current revision of
a credential, or a service. __archive-credential__ and __archive_service__ are
archived revisions of passwords and services and are append-only.

When a credential or a service is updated, it is added to the archive and the
current revision is modified to reflect the newest revision. If the item isn't
saved to the archive, the request will fail and the state of the system stays
the same.

__credential__

* id: uuid4 (string)
* data-type: 'credential' (string)
* revision: incrementing integer (integer)
* name: user-defined friendly name (string)
* credential\_pairs: dict with key/val pairs (string)
* enabled: (boolean)
* data\_key: encrypted data key used to encrypt the credential\_pairs (binary)
* modified\_date: auto-generated date (datetime)

__archive-credential__

* id: uuid4-revision (string)
* data-type: 'archive-credential' (string)
* revision: incrementing integer (current revision + 1) (integer)
* name: user-defined friendly name (string)
* credential\_pairs: dict with key/val pairs (string)
* enabled: (boolean)
* data\_key: encrypted data key used to encrypt the credential\_pairs (binary)
* modified\_date: auto-generated date (datetime)

__service__

* id: user-defined name (should match IAM role) (string)
* data-type: 'service' (string)
* revision: incrementing integer (integer)
* credentials: list of credential ids (string set)
* modified\_date: auto-generated date (datetime)

__archive-service__

* id: user-defined name (should match IAM role) (string)
* data-type: 'service' (string)
* revision: incrementing integer (current revision + 1) (integer)
* credentials: list of credential ids (string set)
* modified\_date: auto-generated date (datetime)

## At-rest encryption model

All metadata in Confidant is stored in clear text, but credential pairs in
credentials are stored encrypted at-rest.

Confidant uses a configured KMS master key to generate data keys. The
encrypted data keys are stored in DynamoDB along with the credential.
The decrypted data keys are kept in memory in the confidant web service
for caching purposes.

When credentials are created or updated, their credential pair information is
encrypted and the data key used to encrypt the pair is recorded with
the credential, in its encrypted form. When credentials are fetched, their
credential pair is decrypted using the data key associated with the credential.
For each credential decryption we make a call to KMS, if the plaintext data key
isn't available in memory.
