#!/usr/bin/env bash
# Run exactly what CI runs, in the same order, with the same tools.
#
# Why this exists
# ---------------
# Twice in one session I pushed a change that passed my local commands and failed CI,
# because my local commands were not CI's commands:
#
#   * `ruff check vuln_intel tests` with the repository's curated `ruff.toml` (S/B/RET/
#     SIM families) caught a bandit subprocess warning that my wider local invocation had
#     silenced with --fix ordering;
#   * the test job installs `hypothesis` and `openapi-spec-validator`, so tests that skip
#     locally actually execute there, and a skipped test is not a passing test.
#
# Neither was hard to find once CI had failed. Both were avoidable by running the job.
#
# Usage:  ./scripts/ci_preflight.sh [--install]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# Use the interpreter this script was invoked with, or PYTHON if set, so a virtualenv
# works without activation. Falling back to bare `python` in a sandbox picks the system
# interpreter and reports "No module named ruff" for a tool that is present.
PY="${PYTHON:-python}"
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PY="${VIRTUAL_ENV}/bin/python"
fi

if [[ "${1:-}" == "--install" ]]; then
  "$PY" -m pip install -q \
    "pytest>=8,<10" "hypothesis>=6,<7" "pyyaml>=6" \
    "openapi-spec-validator>=0.7" "pyflakes>=3,<4" "ruff>=0.6,<1" "mypy>=1.10,<2"
fi

failures=0
step() {
  local name="$1"; shift
  printf '\n=== %s ===\n' "$name"
  if "$@"; then
    printf 'PASS  %s\n' "$name"
  else
    printf 'FAIL  %s\n' "$name"
    failures=$((failures + 1))
  fi
}

# Same order as .github/workflows/vuln-intel.yml.
step "pyflakes" "$PY" -m pyflakes vuln_intel tests
step "ruff (curated rules from ruff.toml)" "$PY" -m ruff check vuln_intel tests
step "mypy (package only)" "$PY" -m mypy
step "pytest (offline, full)" "$PY" -m pytest -q
step "pipeline demo" "$PY" -m vuln_intel.demo

# The workflow only lints `vuln_intel tests`, but scripts/ ships too and a broken script
# is still broken. Report it separately so a failure here is understood as stricter than
# CI rather than identical to it.
step "ruff (scripts/, stricter than CI)" "$PY" -m ruff check scripts

printf '\n'
if (( failures )); then
  printf '%d step(s) failed. This is what CI will do.\n' "$failures"
  exit 1
fi
printf 'All CI steps pass locally.\n'
