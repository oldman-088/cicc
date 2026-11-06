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
# A third lesson, added later, is the one that cost the most to learn:
#
#   * CI is not one environment. The `oracle` job installs pytest, hypothesis, pyyaml
#     and three version-oracle packages — no ruff, no mypy. The runtime-oracle job had
#     no pyyaml at all, and because several test modules are guarded by
#     `pytest.importorskip("yaml")`, its suite was silently SMALLER rather than skipped.
#     A test that compares a declared test count to the collected count therefore
#     failed there while passing locally. This script runs the test job's steps only,
#     so it could not see any of that; `--bare-python PATH` runs the suite in an
#     interpreter with only the test dependencies, which is how that class of failure
#     is caught before pushing.
#
# Usage:  ./scripts/ci_preflight.sh [--install] [--bare-python PATH]
set -uo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.." || exit 1

# Use the interpreter this script was invoked with, or PYTHON if set, so a virtualenv
# works without activation. Falling back to bare `python` in a sandbox picks the system
# interpreter and reports "No module named ruff" for a tool that is present.
PY="${PYTHON:-python}"
if [[ -n "${VIRTUAL_ENV:-}" && -x "${VIRTUAL_ENV}/bin/python" ]]; then
  PY="${VIRTUAL_ENV}/bin/python"
fi

BARE_PY=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --bare-python)
      BARE_PY="${2:-}"
      [[ -n "$BARE_PY" ]] || { echo "--bare-python needs a path" >&2; exit 2; }
      shift 2
      ;;
    --bare-python=*)
      BARE_PY="${1#*=}"
      shift
      ;;
    *)
      [[ "$1" == "--install" ]] && DO_INSTALL=1
      shift
      ;;
  esac
done

if [[ "${DO_INSTALL:-0}" == "1" ]]; then
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

# The oracle job's environment: test tooling only. Anything that depends on ruff, mypy
# or a validator being importable must skip here, not fail — and the suite must still be
# green, because that is what CI runs.
if [[ -n "$BARE_PY" ]]; then
  echo
  echo "--- bare-interpreter suite (mirrors the oracle/runtime-oracle job env) ---"
  step "pytest in $BARE_PY (test deps only)" "$BARE_PY" -m pytest -q
fi

printf '\n'
if (( failures )); then
  printf '%d step(s) failed. This is what CI will do.\n' "$failures"
  exit 1
fi
printf 'All CI steps pass locally.\n'
