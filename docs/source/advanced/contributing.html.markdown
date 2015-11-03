---
title: Contributing
---

# Contributing

## Contributing code

### Sign the Contributor License Agreement (CLA) (not yet available)

We require a CLA for code contributions, so before we can accept a pull request
we need to have a signed CLA. Please send signed copies of the form to TBD.

### File issues in Github

In general all enhancements or bugs should be tracked via github issues before
PRs are submitted. We don't require them, but it'll help us plan and track.

When submitting bugs through issues, please try to be as descriptive as
possible. It'll make it easier and quicker for everyone if the developers can
easily reproduce your bug.

### Submit pull requests

Our only method of accepting code changes is through github pull requests.

## Development guide

### Development using docker

Confidant comes with Dockerfile and docker-compose.yml files. You can use these
to run a local development environment. This environment will launch a local
dynamo (accessible through http://dynamo:7777) a local redis (accessible
through redis://redis:6379) and a local confidant container.

### Quickstart for testing or development

It's possible to start Confidant with authentication and encryption disabled,
to make it easier to test or to do development on portions of confidant that
don't require these features. It's very important to never use this
configuration outside of a testing or development environment, as it disables
everything that makes Confidant safe!

Here's a basic configuration that can be used for test/development:

__service.env__:

```bash
# Use fake AWS credentials
AWS_ACCESS_KEY_ID=1
AWS_SECRET_ACCESS_KEY=1
# Disable all forms of authentication.
# NEVER USE THIS IN PRODUCTION!
USE_AUTH=false
# Disable any use of at-rest encryption.
# NEVER USE THIS IN PRODUCTION!
USE_ENCRYPTION=false
# The region our service is running in.
AWS_DEFAULT_REGION=us-east-1
# The DynamoDB table name for storage.
DYNAMODB_TABLE=confidant-development
# A local dynamodb service.
DYNAMODB_URL=http://dynamo:7777
# Set the gevent resolver to ares; see:
#   https://github.com/surfly/gevent/issues/468
GEVENT_RESOLVER=ares
# Enable debug mode, which will also disable SSLify.
# NEVER USE THIS IN PRODUCTION!
DEBUG=true
# Add a sessions secret, for CSRF protection
SESSION_SECRET=lo8TouG7Bee1ahx7caeyoa6Aic6ku1johjoiyiey
# For ease of development, use frontend code that does not always require
# a grunt build.
STATIC_FOLDER=public
```

Place that configuration into a file called __service.env__ in the root of
Confidant's repo and run:

```bash
docker-compose up
```

Confidant will be available for testing at http://localhost.

By default the docker-compose.yml file has a couple arguments commented that
can be used to make development quicker (__build__ and __volumes__). If you
uncomment __volumes__ the confidant repo will be volume mounted into the
container, which will let you make live modifications to the code without doing
a full docker build. If you uncomment build, and comment out image,
docker-compose up will build the confidant image before starting the
containers.

A reasonable development process is as follows:

1. Uncomment build, comment out image and uncomment volume.
2. Run: docker-compose build
3. Comment out build and uncomment image.
4. Run: docker-compose up
5. Test.
6. Run: docker-compose stop
7. Make changes.
8. Run: docker-compose up

Note that in the above, for most changes you should be able to stop/start the
containers and your changes will apply; however, some changes require a
build. In that case, you can repeat the entire above process.
