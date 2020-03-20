# Contributing

## Code of conduct

This project is governed by [Lyft's code of conduct](https://github.com/lyft/code-of-conduct).
All contributors and participants agree to abide by its terms.

## Contributing code

### Sign the Contributor License Agreement (CLA)

We require a CLA for code contributions, so before we can accept a pull request
we need to have a signed CLA. Please [visit our CLA service](https://oss.lyft.com/cla)
follow the instructions to sign the CLA.

### File issues in Github

In general all enhancements or bugs should be tracked via github issues before
PRs are submitted. We don't require them, but it'll help us plan and track.

When submitting bugs through issues, please try to be as descriptive as
possible. It'll make it easier and quicker for everyone if the developers can
easily reproduce your bug.

### Submit pull requests

Our only method of accepting code changes is through github pull requests.

## Development guide

### Development using docker-compose

A full developer configuration is available, using docker-compose, which uses
local dynamodb, local kms, and a local simplesamplephp.

To start: `docker-compose up`

To test code changes:

1. `docker build -t lyft/confidant .`
1. Kill docker-compose (ctrl-c)
1. `docker-compose up`

Confidant will be accessible at `http://localhost`. The username is `confidant`
and the password is `confidant`.

All configuration settings for this environment are in the `config/development`
directory. If you wish to change any settings, kill the docker compose, make the
change, and start the docker-compose environment back up.
