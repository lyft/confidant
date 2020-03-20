# Changelog

## 6.3.0

* Added support for keeping track of when credentials should be rotated.
  Three new fields have been added to the Credential model:

  * tags: `tags` are a set of strings that can be used to categorize a credential. For instance
  "ADMIN_PRIV" or "EXEMPT_FROM_ROTATION" could be potential tags. We choose to have a list of tags
  rather than a single string because some credentials might fall into multiple categories
  * last_decrypted_date: `last_decrypted_date` explicitly stores when someone viewed a credential.
  Certain credentials can potentially be highly vulnerable and could benefit from being rotated
  the moment the credential pair is viewed.
  * last_rotation_date: `last_rotation_date` stores when a credential was last rotated. Some credentials
  might need to periodically be rotated for security purposes.

  There is also additional logic for calculating when a credential should next be rotated
  given its previous rotation history. This logic lives as the `next_rotation_date` property on the
  Credential object and is not persisted into the DB layer.  To use this logic:

  1. Set an env variable `MAXIMUM_ROTATION_DAYS` which determines how the maximum amount of time before
     a credential should be rotated. By default, `MAXIMUM_ROTATION_DAYS` is 0 so people using this feature
     must explicitly set it.
  1. Set an env variable `ROTATION_DAYS_CONFIG` which is a JSON serialized string. This is just a key value
     config where the key represents a tag (eg: "ADMIN_PRIV") and the value represents the number of days
     that keys with this tag should be rotated. For instance, we could have a `ROTATION_DAYS_CONFIG` that
     looks something like '{"ADMIN_PRIV": 30, "FINANCIAL_DATA": 10}'

* Add a `metadata_only` param to `GET /v1/credentials/<ID>`. For instance, if the request is
  `GET /v1/credentials/123?metadata_only=true`, the response will not contain the credential pairs.
  `metadata_only` defaults to `false` so that it is backwards compatible. The purpose of this
  is to give users finer controls when deciding whether to send back `credential_pairs`.

* Automatically update the `last_decrypted_date` on a credential when the `credential_pairs` are
  sent back to the client. Sending `credential_pairs` to the client implies that a credential has been
  decrypted and is likely to have been read by a human. This is also an OPT IN change.
  An environment variable `ENABLE_SAVE_LAST_DECRYPTION_TIME` must be set to true in order to
  update `last_decrypted_date`.

* Added `config/gunicorn.conf` and `config/logging.conf` files, which can be used to enable structured
  json logs for logging output.

* Updated the docker-compose setup to have a fully functional production-like environment, with
  local dynamodb, local kms, and a local simplesamlphp IDP. The developer environment also has a
  configuration for the PKI, which will generate self-signed certificates.

## 6.2.0

* This release fixes a python3 stacktrace in SAML auth, when using the `SAML_SP_KEY_FILE` setting.

## 6.1.0

* This release adds support for confidant acting as a Certificate Authority,
  using AWS Certificate Manager Private Certificate Authority. Four new endpoints
  have been added:

  * `GET /v1/certificates/<ca>/<cn>`: Have confidant generate a private key, a CSR,
  and have it issue a certificate against the provided CA, with the provided CN. A
  list of SANs can be provided via arguments: `?san=<domain>&san=<domain>` The validity
  in number of days can be provided via arguments: `?validity=120` The maximum validity
  is controlled server side via a configuration setting.
  * `POST /v1/certificates/<ca>`: Generate a private key and CSR from the client side,
  and have confidate issue a certificate against the provided CA. SAN and validity can
  be set via a json post body: `{"san": ["domain", "domain"], "validity": 120}`
  * `GET /v1/cas`: Get a list of configured CAs, their certificate and certificate chains,
  and a dictionary of key/value tags set on the CA in AWS.
  * `GET /v1/cas/<ca>`: Get the certificate, certificate chain, and a dict of tags set on
  the CA in AWS.

  The implementation supports multiple CAs. For configuration information, see [the
  certificate authority settings section in the docs](https://lyft.github.io/confidant/configuration.html#certificate-authority-settings).

## 6.0.0

* This release is a breaking release. This release slightly changes the API
  responses. Though the changes should be backwards incompatible, we're now
  explicitly returning all fields in returns, rather than not including
  fields that have nil values in the json. Clients that expect fields to not
  exist could be affected by this change. The offical python client has been
  tested against these changes, but there's a number of unofficial libraries
  that you will want to test, if you're using one of them.
* DEPRECATION NOTICE: This will be the last confidant release that will support
  python2.
* DEPRECATION NOTICE: This will be the last confidant release that will support
  blind credentials. If you're using blind credentials, we recommend switching
  to standard credentials, and protecting access to them using the new access
  control (ACL) support hooks to provide fine-grained access control.
* Confidant is now python3 compatible, and tested against python 3.6, 3.7 and
  3.8. If you see any python3 related issues, please open an issue.
* Confidant now includes an access control plugin framework, with a default
  plugin, `confidant.authnz.rbac:default_acl`, which implements the existing
  access control behavior of confidant. The `ACL_MODULE` setting can be used
  to define your own ACL behavior; see the [ACL docs](https://lyft.github.io/confidant/advanced/acls/)
  for information about how to apply fine-grained access controls to specific
  resources and actions.
* kmsauth was upgraded with a more efficient LRU implementation, which allows
  for higher concurrency.
* The frontend and backend have been refactored to only provide sensitive data
  where necessary. For example, previously, when viewing a service, the
  credentials for that service were included in the response. Now when the
  frontend fetches a service, it only fetches credential metadata that it uses
  for display purposes. Similarly, the history view no longer fetches or
  displays sensitive information. These changes were made to support fine-grained
  access controls.
* The resources and history view list panels no longer combine resources in the
  view, but include a resource type toggle, to make it easier to find resources.
* The history backend endpoints that list resources now support paged results.
  Future releases will expand this to all endpoints that list resources. Default
  behavior for these endpoints is to not page results. Clients can limit the
  page size via an argument. It's also possible to force paging for these
  via the `HISTORY_PAGE_LIMIT` setting.
* New backend endpoints have been added to support reverting credential and
  service resources, rather than needing to do an edit of resources, with all
  fields. This was in support of adding fine-grained access controls, but also
  makes reverting resources trivial from the client side.
* `GET /v1/services/<id>` now supports a `metadata_only=[True|False]` argument
  which can be used to only include metadata in the response.
* Permissions hints are included in the response of resource endpoints, to
  allow the UI (and other clients) to adjust their behavior based on permissions
  available.
* More detailed audit logs have been added for user actions, such as get/update credential,
  and get/update service.
* Google OAuth support has been updated to work with the new Google Sign-In APIs,
  rather than the older Google+ Sign-In APIs.

## 5.2.0

* Python3 fix in function ``load_private_key_pem`` in ``confidant.lib.cryptolib``

## 5.1.0

* Python3 fix in class ``CipherManager`` in ``confidant.ciphermanager``

## 5.0.1

* Packaging fixes for docker

## 5.0.0

* This is a breaking release. This release slightly changes the values needed
  for the ``AUTH_KEY``, ``USER_AUTH_KEY``, and ``KMS_MASTER_KEY`` settings.
  The previous way these settings were set were to use the alias name, without
  an ``alias/`` prefix. In this release we switched to using the kmsauth
  library for kms authentication support, which supports aliases and ARNs for
  keys, which means that for these three settings, it's necessary to add an
  ``alias/`` prefix to the value. So, for example, if your setting was
  ``my-auth-key``, the new value would be ``alias/my-auth-key``. Though this
  change of behavior was limited to kmsauth, for consistency we also changed
  ``KMS_MASTER_KEY`` to use the same behavior. For all three settings, it's
  also now possible to use ARNs as values, instead of just key aliases.
* confidant now supports python2 and python3.
* Requirements have been updated to resolve some reported security
  vulnerabilities in a few of the frozen requirements. A library affecting
  user sessions was upgraded which will cause users to be logged out after
  upgrade, which means if you're doing a rolling upgrade, that during the
  upgrade, you may have users that seemingly randomly get logged out. After
  a finished upgrade, users should only be logged out once, if they're
  currently logged in.

## 4.4.0

* Use ``dict`` and ``set`` in pynamo models rather than ``{}`` and ``set()``,
  to avoid potential corrupted data in model saves. Based on how confidant
  currently uses the pynamo models, the default arguments can't lead to data
  corruption, but to avoid potential future issues, we're fixing the default
  args to not be mutable.

## 4.3.1

* Packaging fix

## 4.3.0

* Case insentive sort for service and credential list API responses

## 4.2.0

* Don't in-memory cache the USERS\_FILE, but re-read it every time, so that
  the confidant process doesn't need to restarted whenever this file changes.

## 4.1.0

* Switch from python-saml to python3-saml.


## 4.0.0

* This is a breaking release. This change upgrades the `LegacyBooleanAttributes`
  to `BooleanAttributes`, which saves data in a new format. Once you upgrade
  to this version, you must run the migrate\_bool\_attribute maintenance
  script immediately after upgrading, which will convert all old data into
  the new format and prevent further issues with Pynamo upgrades.

## 3.0.0

* This is a breaking release, if you're using blind credentials. This change
  upgrades to using pynamodb 3.2.1. If you're using blind credentials, it's
  necessary to first upgrade to confidant 2.0.0, run the
  migrate\_set\_attribute maintenance script, then upgrade to this version.
  This is due to a breaking change in pynamodb itself, which requires using
  specific versions of pynamodb to migrate the underlying data.

## 2.0.1

* Added additional logging in the v1 routes.
* Updated the migration script to include both Service and BlindCredential
  migrations, as well as checks to ensure the migration was successful.

## 2.0.0
WARNING: If you upgrade to this version, any new writes to blind credentials
will be in a format that is only compatible in 1.11.0 forward. If you've
upgraded and need to downgrade, you should downgrade to 1.11.0. This is only
a concern if you're using blind credentials. If you're using blind credentials,
see the [upgrade instructions](https://github.com/lyft/confidant/blob/master/docs/source/basics/upgrade.html.markdown)
for more detailed information about this breaking change.

* Added support for a maintenance mode, which will disable all writes to
  confidant via the API. This allows you to put confidant into a maintenance
  mode which will let you do maintenance actions via scripts, but will disallow
  all write actions via the API while you're performing the maintenance.
  This is useful for data migrations, or during periods where you want to
  ensure no confidant changes are being made. See the docs for
  MAINTENANCE\_MODE and MAINTENANCE\_MODE\_TOUCH\_FILE settings.
* Upgraded pynamodb to 2.2.0, to support migration of UnicodeSetAttribute for
  blind credentials in DynamoDB.
* Changed dynamo models to use LegacyBooleanAttribute, to allow for backwards
  compatibility for the data models. In a future version we'll require a
  migration for dynamo data to the new BooleanAttribute format used in
  PynamoDB.

## 1.11.0

* Upgrade PynamoDB requirement to 1.5.4

## 1.10.1

* Fix an issue in the angularjs frontend where credential values were having whitespace trimmed.

## 1.10.0

* Upgrade gevent and greenlet for CVE-2016-5180 and gevent/gevent#477

## 1.9.0

* piptools upgrade of transitive dependencies. Most notably this was run to
  upgrade gunicorn to 19.7.1, which allows for using FORWARDED\_ALLOW\_IPS in
  the environment, as well as any other newer gunicorn settings.

### 1.8.0

* Switch LRU for in-memory cache from an inefficient python implementation to
  lru-dict.

### 1.7.0

* Update appdirs requirement

### 1.6.0

* Update python-saml for CVE-2016-1000252.

### 1.5.1

* Fix docker\_push.sh

### 1.5.0

* Added a feature to disable the credential conflict checks; see configuration
  docs for IGNORE\_CONFLICTS

### 1.4.0

* Added support for sending basic webhooks; see configuration docs for
  WEBHOOK\_URL

### 1.3.0

* Update statsd depencency from 3.1 to 3.2.1

### 1.2.0

* Switch to doing semver in a more proper way. Though generally all previous
  releases were backwards compatible, we had been releasing features in point
  releases rather than minor releases. Going forward, breaking changes will be
  in major releases, features in minor releases, and bugfixes in point
  releases. When dependencies are updated we'll consider the impact of the
  dependency update to determine the semver release
* Made the XSRF cookie name configurable. See the configuration docs for how to
  changet he XSRF cookie name.

### 1.1.21

* Move scripts into the confidant module to be able to use the scripts when pip
  installed

### 1.1.20

* Added changes and settings for better performance in confidant. See the
  performance section in the configuration docs

### 1.1.19

* Important change: the location of the wsgi.py has moved inside of the
  confidant module to make the pypi package runnable. This changes the gunicorn
  invocation from `gunicorn wsgi:app -k gevent` to `gunicorn confidant.wsgi:app
  -k gevent`

### 1.1.16 - 1.1.18

* Getting the pypi package into a working state

### 1.1.15

* Split the client away from the confidant repo

### 1.1.14

* Security fix: While preparing for the 1.1 stable release Lyft found a KMS
  authentication vulnerability in the unreleased 1.1 branch while performing an
  audit of the code. The vulnerability was introduced while adding the scoped auth
  key feature (for limiting authentication keys and services to specific AWS
  accounts), where the key was not properly checked after decryption. This check is
  an additional verification to add additional safety on-top of the IAM policy of
  your KMS keys. If IAM policy allows users to use KMS keys without limits on
  encryption context, a KMS key that wasn't intended to be used for auth, could be
  used for auth.

### 1.1.13

versions 1.1.0 - 1.1.12 were pre-release versions of the 1.1 branch. The
versions were generally increased for changes to the client, during internal
updates at Lyft. Since 1.1.13 is the first release, we'll be tracking changes
in the changelog from this point on. Future releases will track all changes,
even in unreleased branches.

* Security fix: We discovered when adding tests after a refactor of some of the
  KMS authentication code that confidant wasn't properly checking the
  expiration of KMS auth tokens. If tokens were able to be exfiltrated from a
  service, they could be used indefinitely. This has now been fixed, and any
  tokens that are expired will now correctly fail to authenticate.
* Feature: Server-blinded secret support (called blind credentials in code and
  interface). A new type of secret that confidant simply stores, assuming it's
  been encrypted prior to being passed in. Makes it possible to have
  credentials mapped to services where only the service has the ability to
  decrypt the secret.
* Refactor: The user authentication code went through a refactor to be abstract
  and support multiple forms of authentication in a configurable way. The
  authentication flow for users has also changed along with this refactor.
  There's now a proper login/logout flow, and users will be presented with an
  interface before they're required to authenticate. When a user's session has
  expired, they'll be redirected to a loggedout page.
* Feature: SAML authentication support for user authentication.
* New python dependencies (for SAML): python-saml
* New system dependencies (for SAML): libxml2-dev libxmlsec1-dev
* Feature: Header authentication support for user authentication.
* Feature (and new default): Added support for secure cookies for session
  management. This removes the dependency on redis. New settings were added to
  control the lifetime of secure cookie sessions.
* Feature: Extensible metadata for secrets and blind secrets.
* Feature: AWS account scoping for services. If you're using multiple AWS
  accounts, it's possible to limit access to services from specific accounts by
  using multiple KMS keys for KMS authentication.
* Feature: A new version of KMS auth (version 2). The new version of KMS auth
  can allow service-to-service authentication, or user-to-service
  authentication. It's possible to use the same authentication key for both
  service-to-service authentication and user-to-service authentication, but it's
  recommended to make a new KMS key specific to user authentication, unless
  care is taken with IAM policy and your KMS auth key grants are updated to
  require KMS auth v2 (a maintenance script is included with this purpose). By
  default confidant will only allow service-to-service authentication.
* Feature: Added a config setting to disable KMS auth key grant management. If
  you prefer to manage your KMS auth via IAM policy rather than grants, this
  option will ensure that no grants are added to your keys. A maintenance
  script is included to purge any grants that may already exist on your key.
* Feature: Added an opinionated confidant client.
* Feature: Add a formatter for get\_service output, with a few export formats
  (combined credential pair output, bash variable export format, etc).
* Feature: Added a REST endpoint to provide configuration information to
  clients, to help them configure themselves. It's also possible to add a set
  of custom configuration to be sent to clients along with the server generated
  config, via the CLIENT\_CONFIG setting.
* Feature: Added a setting, SECRETS\_BOOTSTRAP, that can either be a base64
  encoded, KMS encrypted, YAML dict, or a file path that contains the base64
  encoded, KMS encrypted, YAML dict. A maintenance script is included that will
  let you generate the encrypted and encoded form of this dict from a yaml
  file. All of confidant's sensitive settings can be loaded from this bootstrap
  data, allowing you to bootstrap confidant's own secrets.
* Feature: A new setting, DYNAMODB\_CREATE\_TABLE, has been added to allow
  confidant to create its own dynamodb table, if it doesn't exist yet.
* Feature: Automatic secret generation for credential pairs from angular UI.
* Fix: performance fixes for angularjs (disabling some debugging features and
  ignoring grants when grants are disabled).
