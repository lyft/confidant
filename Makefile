# bash needed for pipefail
SHELL := /bin/bash

test: test_unit

test_unit:
	mkdir -p build
	nosetests --with-coverage --with-path=confidant tests/unit

.PHONY: compile_deps # freeze requirements.in to requirements3.txt
compile_deps:
	./pip-compile.sh
