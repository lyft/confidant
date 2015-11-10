test: test_lint test_unit

test_lint:
	mkdir -p build
	set -o pipefail; flake8 | sed "s#^\./##" > build/flake8.txt || (cat build/flake8.txt && exit 1)

test_unit:
	# Disabled for now. We need to fully mock AWS calls.
	echo nosetests --with-path=confidant tests/unit
