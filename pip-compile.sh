#!/bin/bash
#
# This build script is based on work from https://github.com/envoyproxy/envoy/blob/master/docs/build.sh

set -e
set -x

source_venv() {
  VENV_DIR=$1
  if [[ "$VIRTUAL_ENV" == "" ]]; then
    if [[ ! -d "${VENV_DIR}"/venv ]]; then
      virtualenv "${VENV_DIR}"/venv --python=python3
    fi
    source "${VENV_DIR}"/venv/bin/activate
  else
    echo "Found existing virtualenv"
  fi
}

SCRIPT_DIR=$(dirname "$0")

source_venv piptools_venv
pip install -r "${SCRIPT_DIR}"/piptools_requirements.txt
pip install pip-tools
cd "${SCRIPT_DIR}"
pip-compile
