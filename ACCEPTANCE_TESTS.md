# ACCEPTANCE TESTS — Agent 1 scope (2026-11-05)

Run (exact commands):
1. `cd apps/api && . .venv/bin/activate && python -m pytest -q -p no:cacheprovider` → 155 passed (unit + HTTP integration; incl. 7 real-PG via `-k "postgres or pg"`, 1 live-GitHub).
2. `cd apps/web && npm test && npx tsc --noEmit && npm run build` → 23 pass, tsc OK, build OK.
3. Live E2E: `API=http://127.0.0.1:8000 WEB=http://127.0.0.1:3000 WRITE_TOKEN=... READ_TOKEN=... python scripts/e2e_check.py` → 22/22 PASS (modes labeled: LIVE-API / LIVE-BFF / SIMULATED-FIXTURE; real-PG separate).
4. i18n: `npm test` includes tests/i18n.test.mjs (en/ar key parity 188/188, RTL map).

Acceptance criteria per feature: see REQUIREMENTS_TRACEABILITY.md and docs/COORDINATION_ARCHITECTURE.md.
