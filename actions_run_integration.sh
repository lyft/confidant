#!/bin/bash

cd /srv/confidant
apt-get update && apt-get install -y python3-dev openssl libssl-dev gcc pkg-config libffi-dev libxml2-dev libxmlsec1-dev
pip install -r piptools_requirements3.txt && pip install -r requirements3.txt
make test_integration
