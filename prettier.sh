#!/bin/bash
echo "🚀 Running Python Prettier (Black + isort + flake8)..."

black . --exclude '\.venv'
isort . --skip .venv
flake8 . --exclude=.venv

echo "✅ Done!"
