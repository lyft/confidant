# bash needed for pipefail
SHELL := /bin/bash

clean:
	find . -name "*.pyc" -delete

up:
	docker-compose up

down:
	docker-compose down

docker_build: clean
	docker build -t lyft/confidant .

docker_test: docker_build docker_test_unit docker_test_integration docker_test_frontend down

docker_test_unit:
	docker-compose run --rm --no-deps confidant make test_unit

docker_test_integration:
	docker-compose run --rm confidant make test_integration

docker_test_frontend:
	docker-compose run --rm confidant make test_frontend

test: test_unit test_integration test_frontend

test_integration: clean
	mkdir -p build
	test -d /venv && source /venv/bin/activate || true
	pytest --strict tests/integration

test_unit: clean
	mkdir -p build
	test -d /venv && source /venv/bin/activate || true
	pytest --strict --junitxml=build/unit.xml --cov=confidant --cov-report=html --cov-report=xml --cov-report=term --no-cov-on-fail tests/unit

test_frontend:
	grunt test

.PHONY: compile_deps # freeze requirements.in to requirements3.txt
compile_deps:
	./pip-compile.sh

.PHONY: build_docs
build_docs:
	./docs/build.sh
