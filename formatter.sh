#!/bin/bash
VENV_PYTHON="./.venv/bin/python3"

echo "🚀 Running Python Formatter (Black + isort + flake8)..."

$VENV_PYTHON -m black . --exclude '\.venv'
$VENV_PYTHON -m isort . --skip .venv
$VENV_PYTHON -m flake8 . --exclude=.venv

echo "✅ Done!"
