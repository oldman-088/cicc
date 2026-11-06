#!/usr/bin/env bash
# Static check: no hardcoded secrets in Docker/Compose/env-example files.
# Scans for common secret patterns. Exits non-zero on any finding.
set -euo pipefail
cd "$(dirname "$0")/.."

PATTERNS='(password|passwd|secret|token|api[_-]?key)\s*[:=]\s*["'"'"']?[A-Za-z0-9_\-]{8,}'
FOUND=0
for f in $(git ls-files 'apps/*/Dockerfile' 'docker-compose*.yml' '.env.example' 'apps/api/requirements*.txt'); do
  # allow placeholder values in .env.example (they are examples, not real secrets)
  if grep -nEi "$PATTERNS" "$f" | grep -viE 'example|placeholder|changeme|sqlite|your-|xxx|<|\$\{'; then
    echo "POSSIBLE SECRET in $f:"
    grep -nEi "$PATTERNS" "$f" | grep -viE 'example|placeholder|changeme|sqlite|your-|xxx|<|\$\{'
    FOUND=1
  fi
done
if [ "$FOUND" -ne 0 ]; then
  echo "SECRET SCAN FAILED"
  exit 1
fi
echo "SECRET SCAN PASSED (no hardcoded secrets in deployment files)"
