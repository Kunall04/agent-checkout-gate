#!/usr/bin/env sh
# One-take demo. See scripts/demo.py for what each step proves.
set -e
cd "$(dirname "$0")/.."
exec "${PYTHON:-.venv/bin/python}" scripts/demo.py "$@"
