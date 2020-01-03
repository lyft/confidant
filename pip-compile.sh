#!/bin/bash
#
# This build script is based on work from https://github.com/envoyproxy/envoy/blob/master/docs/build.sh

set -e
set -x

source_venv() {
  VENV_DIR=$1
  if [[ "$VIRTUAL_ENV" == "" ]]; then
    if [[ ! -d "${VENV_DIR}"/venv ]]; then
      virtualenv "${VENV_DIR}"/venv --no-site-packages --python=python3
    fi
    source "${VENV_DIR}"/venv/bin/activate
  else
    echo "Found existing virtualenv"
  fi
}

SCRIPT_DIR=$(dirname "$0")

source_venv piptools_venv
pip install -r "${SCRIPT_DIR}"/piptools_requirements3.txt
pip install pip-tools
pip-compile --output-file "${SCRIPT_DIR}"/requirements3.txt "${SCRIPT_DIR}"/requirements.in
