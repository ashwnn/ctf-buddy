#!/usr/bin/env bash
# Full reset of the p2 fixture. THIS SCRIPT DELETES THE FIXTURE'S NAMED VOLUME.
# Safe only because the fixture holds no data worth keeping.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

if ! command -v docker >/dev/null 2>&1; then
  echo "reset: docker is not installed" >&2
  exit 2
fi

echo "reset: removing containers and the fixture volume"
docker compose down -v --remove-orphans

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "reset: restoring tracked fixture files to HEAD"
  git restore --source=HEAD --staged --worktree -- . || true
fi

echo "reset: rebuilding and starting"
docker compose up -d --build

echo "reset: waiting for the service to answer"
for _ in $(seq 1 30); do
  if curl -fsS "http://127.0.0.1:8081/api.php?action=healthz" >/dev/null 2>&1; then
    echo "reset: fixture is up (http://127.0.0.1:8081)"
    exit 0
  fi
  sleep 2
done

echo "reset: fixture did not become healthy; recent logs:" >&2
docker compose logs --tail 40 >&2 || true
exit 1
