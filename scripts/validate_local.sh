#!/usr/bin/env bash
# Local validation for the System Health & Operations subsystem.
# Runs API tests, web tests, typecheck and production build.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== API: install + pytest =="
cd apps/api
python3 -m venv .venv 2>/dev/null || true
. .venv/bin/activate
pip install -q -r requirements-dev.txt
python -m pytest -q

echo "== Web: npm ci + tests + typecheck + build =="
cd ../web
npm ci --no-audit --no-fund
npm test
npm run typecheck
npm run build

echo "ALL LOCAL CHECKS PASSED"
