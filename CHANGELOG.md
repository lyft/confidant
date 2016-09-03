# Changelog

## 1.1

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
