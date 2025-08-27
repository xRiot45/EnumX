#!/bin/bash
echo "🚀 Running Python Formatter (Black + isort + flake8)..."

black . --exclude '\.venv'
isort . --skip .venv
flake8 . --exclude=.venv

echo "✅ Done!"
