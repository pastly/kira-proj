#!/usr/bin/env bash
set -eu
export MYPYPATH=.mypy_out
mypy ugh tests
coverage run --branch --source=ugh -m pytest --capture=no tests/unit tests/integration -vv || true
coverage report
coverage html
