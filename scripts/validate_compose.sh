#!/usr/bin/env bash
# Docker/Compose validation for the CICC ops stack.
# REQUIRES Docker — the Arena sandbox has no Docker, so this was NOT executed
# there; run it in any environment with Docker available.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== docker compose build =="
docker compose build

echo "== docker compose up =="
docker compose up -d

echo "== wait for API readiness =="
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:8000/ready >/dev/null; then break; fi
  sleep 2
done

echo "== probes =="
curl -sf http://127.0.0.1:8000/live
curl -sf http://127.0.0.1:8000/ready
curl -sf http://127.0.0.1:8000/health
curl -sf "http://127.0.0.1:8000/api/v1/ops/overview" | head -c 200; echo

echo "== web proxy checks =="
for i in $(seq 1 30); do
  if curl -sf http://127.0.0.1:3000/api/health >/dev/null; then break; fi
  sleep 2
done
curl -sf http://127.0.0.1:3000/api/health
curl -sf http://127.0.0.1:3000/ | grep -o "CICC" | head -1

echo "== persistence check: ops DB volume exists =="
docker compose exec -T api sh -c 'test -f /data/ops.db && echo ops-db-present'

echo "== shutdown =="
docker compose down
echo "COMPOSE VALIDATION PASSED"
