# bash needed for pipefail
SHELL := /bin/bash

test: test_unit

test_unit:
	nosetests --with-coverage --with-path=confidant tests/unit
