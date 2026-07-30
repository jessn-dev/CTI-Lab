#!/bin/bash
# Tear down the lab. Pass --wipe to also delete all data volumes (fresh start).
set -euo pipefail
cd "$(dirname "$0")/.."   # scripts live in bin/; run from the repo root

if docker compose version >/dev/null 2>&1; then DC="docker compose"; else DC="docker-compose"; fi

if [ "${1:-}" = "--wipe" ]; then
    echo "Stopping lab and REMOVING all data volumes..."
    $DC down -v
else
    echo "Stopping lab (data volumes kept). Use --wipe to remove them."
    $DC down
fi
