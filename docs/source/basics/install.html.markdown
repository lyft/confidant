---
title: Installation
---

# Docker installation

## To run confidant in Docker

It's necessary to export your configuration variables before running confidant.
You can either specify them as multiple -e options, or you can put them into an
an environment file and use --env-file.

```bash
docker pull lyft/confidant
docker run -t confidant --env-file my_config
```

## To build the image

If you want to build the image and store it in your private registry, you can
do the following:

```bash
git clone https://github.com/lyft/confidant
cd confidant
docker build -t confidant .
```

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
sudo apt-get install -y python python-pip python-dev build-essential libffi-dev
cd /srv/confidant
virtualenv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
```

## Build the frontend

```bash
cd /srv/confidant/confidant
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
gunicorn wsgi:app --workers=2 -k gevent
```

That's it. See the configuration documentation about how to configure and run.
