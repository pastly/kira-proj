#!/usr/bin/env bash
set -eu
export MYPYPATH=.mypy_out
mypy rela tests
#coverage run --branch --source=rela -m pytest --capture=no tests/unit tests/integration || true
coverage run --branch --source=rela -m pytest --capture=no tests/unit tests/integration -vv || true
coverage report
coverage html
