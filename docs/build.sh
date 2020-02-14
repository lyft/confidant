#!/bin/bash
#
# This build script is based on work from https://github.com/envoyproxy/envoy/blob/master/docs/build.sh

set -e

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

# We need to set CONFIDANT_DOCS_VERSION_STRING and CONFIDANT_DOCS_RELEASE_LEVEL for Sphinx.
# We also validate that the tag and version match at this point if needed.
if [ -n "$TRAVIS_TAG" ]
then
  # Check the git tag matches the version number in the VERSION file.
  VERSION_NUMBER=$(cat VERSION)
  if [ "v${VERSION_NUMBER}" != "${TRAVIS_TAG}" ]; then
    echo "Given git tag does not match the VERSION file content:"
    echo "${TRAVIS_TAG} vs $(cat VERSION)"
    exit 1
  fi
  # Check the version_history.rst contains current release version.
  grep --fixed-strings "$VERSION_NUMBER" docs/root/intro/version_history.rst \
    || (echo "Git tag not found in version_history.rst" && exit 1)

  # Now that we now there is a match, we can use the tag.
  export CONFIDANT_DOCS_VERSION_STRING="tag-$TRAVIS_TAG"
  export CONFIDANT_DOCS_RELEASE_LEVEL=tagged
  export CONFIDANT_BLOB_SHA="$TRAVIS_TAG"
else
  BUILD_SHA=$(git rev-parse HEAD)
  VERSION_NUM=$(cat VERSION)
  export CONFIDANT_DOCS_VERSION_STRING="${VERSION_NUM}"-"${BUILD_SHA:0:6}"
  export CONFIDANT_DOCS_RELEASE_LEVEL=pre-release
  export CONFIDANT_BLOB_SHA="$BUILD_SHA"
fi

SCRIPT_DIR=$(dirname "$0")
BUILD_DIR=build_docs
[[ -z "${DOCS_OUTPUT_DIR}" ]] && DOCS_OUTPUT_DIR=generated/docs
[[ -z "${GENERATED_RST_DIR}" ]] && GENERATED_RST_DIR=generated/rst
[[ -z "${GENERATED_AUTOGEN_RST_DIR}" ]] && GENERATED_AUTOGEN_RST_DIR=generated/rst/autogen

rm -rf "${DOCS_OUTPUT_DIR}"
mkdir -p "${DOCS_OUTPUT_DIR}"

rm -rf "${GENERATED_RST_DIR}"
mkdir -p "${GENERATED_RST_DIR}"

source_venv "$BUILD_DIR"
pip install -r "${SCRIPT_DIR}"/requirements.txt

rsync -av "${SCRIPT_DIR}"/root/ "${SCRIPT_DIR}"/conf.py "${GENERATED_RST_DIR}"

export EXIT_ON_BAD_CONFIG='false'
set -x
sphinx-apidoc -o "${GENERATED_AUTOGEN_RST_DIR}" -T -P ../confidant
sphinx-build --keep-going -b html "${GENERATED_RST_DIR}" "${DOCS_OUTPUT_DIR}"
