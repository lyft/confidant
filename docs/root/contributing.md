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

This guide assumes you're using docker desktop, which includes docker, and
docker-compose.

A full developer configuration is available, using compose, which uses
local dynamodb, local kms, and a local simplesamplephp. We have quick make
aliases, so it's not necessary to learn the details of docker-compose.

### Starting confidant

To start: `make up`

To test code changes:

1. Kill docker-compose (ctrl-c)
1. `make docker_build`
1. `make up`

Confidant will be accessible at `http://localhost`. The username is `confidant`
and the password is `confidant`.

All configuration settings for this environment are in the `config/development`
directory. If you wish to change any settings, kill the docker compose, make the
change, and start the docker-compose environment back up.

### Running tests

The easiest way to run the tests is through docker-compose as well, as both unit
and integration test suites can be run via compose.

To run the full test suite (minus pre-commit):

```bash
# See the target in the make file; this runs build, unit, integration and down
make docker_test
```

To run only unit tests:

```bash
make docker_build
make docker_test_unit
```

To run only integration tests:

```bash
make docker_build
make docker_test_integration
```

Lint tests are through pre-commit, so it's necessary to [install/run precommit](https://pre-commit.com/#install)
first. To run pre-commit:

```bash
pre-commit run --all-files
```

If you want to have pre-commit auto-run when committing:

```bash
pre-commit install
```
