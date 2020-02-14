# Using the Confidant client

## Installation

Make a virtualenv and install pip requirements:

```bash
virtualenv venv
source venv/bin/activate
pip install confidant-client
```

## Configuration

The client will automatically look in ~/.confidant and /etc/confidant/config,
in order for its configuration. The client does not merge the config. If
~/.confidant is found, it will use that and ignore the file in /etc. Config can
be specified in either YAML or JSON format. The following configuration is
supported, with the listed defaults:

```yaml
default:
  url: None
  auth_key: None
  auth_context: {}
  token_lifetime: 10
  token_version: 2
  token_cache_file: '/run/confidant/confidant_token'
  assume_role: None
  region: None
  retries: 0
  backoff: 1
```

The configuration file supports profiles, which let you specify multiple
environments in the same file. For instance:

```yaml
default:
  url: https://confidant-production.example.com
  auth_key: authnz-production
  auth_context:
    from: rlane
    to: confidant-production
    user_type: user
  token_cache_file: '/run/confidant/default_confidant_token'
  region: us-east-1
staging:
  url: https://confidant-staging.example.com
  auth_key: authnz-staging
  auth_context:
    from: rlane
    to: confidant-staging
    user_type: user
  token_cache_file: '/run/confidant/staging_confidant_token'
  region: us-east-1
development:
  url: https://confidant-development.example.com
  auth_key: authnz-development
  auth_context:
    from: rlane
    to: confidant-development
    user_type: user
  token_cache_file: '/run/confidant/staging_confidant_token'
  region: us-east-1
```

Here's an example for a client configuration for a service:

```yaml
default:
  url: https://confidant-production.example.com
  auth_key: authnz-production
  auth_context:
    from: serviceA-production
    to: confidant-production
    user_type: service
  token_cache_file: '/run/confidant/default_confidant_token'
  region: us-east-1
```

## Usage

The confidant client is a collection of subcommands. You can get a full listing
of subcommands and client arguments via the help documentation:

```bash
confidant --help
```

You can also get help that's specific to a particular subcommand:

```bash
confidant get_service --help
```

There's both global arguments and subcommand specific arguments that can be
set. For the most part all global arguments can be set in configuration, rather
than being passed in. However, if you'd like to override particular
configuration settings from the configuration file, you can override them
directly on the CLI. Note that the arguments must be properly ordered: global
arguments must be specific before subcommands and subcommand arguments must be
specified after the subcommand.

## Reformatting get\_service output

The confidant client also comes with a reformatter for get\_service output, to
make the credential pairs easier to directly use. It's a separate CLI command
that can be chained together with the confidant client. For example:

```bash
confidant get_service --service serviceA-production | confidant-format --out-format env_export --out /run/confidant/env
```

By default the formatter's input and output is stdin and stdout, but it's
possible for the formatter to read in from files and write out to files. For
example:

```bash
confidant get_service --service serviceA-production > /run/confidant/raw
confidant-format --in /run/confidant/raw --out /run/confidant/env --out-format env_export
```
