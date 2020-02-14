# bash needed for pipefail
SHELL := /bin/bash

test: test_unit

test_unit:
	mkdir -p build
	pytest --strict --junitxml=build/unit.xml --cov=confidant --cov-report=html --cov-report=xml --cov-report=term --no-cov-on-fail tests/unit

.PHONY: compile_deps # freeze requirements.in to requirements3.txt
compile_deps:
	./pip-compile.sh

.PHONY: build_docs
	./docs/build.sh
