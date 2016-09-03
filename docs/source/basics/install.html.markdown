---
title: Installation
---

# Quickstart for testing

If you just want to checkout Confidant and aren't looking to deploy it into
production, it's possible to get started without any external dependencies.
Check out the [test and development quickstart](../../advanced/contributing/#quickstart-for-testing-or-development)
for this.

Note that you should _never_ run with this quickstart configuration in production.

# Docker installation

## To run confidant in Docker

It's necessary to export your configuration variables before running confidant.
You can either specify them as multiple -e options, or you can put them into an
an environment file and use --env-file.

```bash
docker pull lyft/confidant
docker run --env-file my_config -t lyft/confidant
```

## To build the image

If you want to build the image and store it in your private registry, you can
do the following:

```bash
git clone https://github.com/lyft/confidant
cd confidant
docker build -t lyft/confidant .
```

# pip installation

Warning: this is still a work in progress and it may not be working right now.
We'll remove this warning when we have pip installation fully working.

1. Using Ubuntu or Debian (please help with non-Ubuntu/Debian install
   instructions!)
1. Using gunicorn as the wsgi server
1. venv location: /srv/confidant/venv

## Make a virtualenv and install pip requirements

```bash
sudo apt-get install -y python python-pip python-virtualenv python-dev build-essential libffi-dev libxml2-dev libxmlsec1-dev
cd /srv/confidant
virtualenv venv
source venv/bin/activate
pip install -U pip
pip install confidant
deactivate
```

Note that the pip package includes the minified, generated frontend artifacts,
in the dist directory. This can be configured via the STATIC_FOLDER setting.

# Manual installation

Assumptions:

1. Using Ubuntu or Debian (please help with non-Ubuntu/Debian install
   instructions!)
1. Using gunicorn as the wsgi server
1. Installation location: /srv/confidant/venv
1. venv location: /srv/confidant/venv
1. node\_modules location: /srv/confidant/node\_modules

## Clone Confidant

```bash
cd /srv
git clone https://github.com/lyft/confidant
```

## Make a virtualenv and install pip requirements

```bash
sudo apt-get install -y python python-pip python-virtualenv python-dev build-essential libffi-dev libxml2-dev libxmlsec1-dev
cd /srv/confidant
virtualenv venv
source venv/bin/activate
pip install -U pip
pip install -r requirements.txt
deactivate
```

## Build the frontend

```bash
cd /srv/confidant
sudo apt-get install -y ruby-full npm nodejs nodejs-legacy git git-core
gem install compass
npm install grunt-cli
npm install
node_modules/grunt-cli/bin/grunt build
```

## Run confidant

It's necessary to export your configuration variables before running confidant.
The easiest method is to source a file that exports your environment before
running confidant.

```bash
source my_config
cd /srv/confidant
source venv/bin/activate
gunicorn confidant.wsgi:app --workers=2 -k gevent
```

That's it. See the configuration documentation about how to configure and run.
