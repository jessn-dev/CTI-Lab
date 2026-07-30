#!/bin/bash
# ==============================================================================
# B2 Part 2 — benchmark the two LLM honeypots head to head (shelLM vs beelzebub).
# Runs the same command sequence + consistency probes against both, on the same
# local model, and writes a scored Markdown report + transcripts to reports/.
# Both LLM honeypots must be up (compose/shellm.yml + compose/beelzebub.yml) with
# Ollama running. Pass-through args are forwarded (e.g. --trials 5, --only shelLM).
# ==============================================================================
set -e
cd "$(dirname "$0")/.."   # scripts live in bin/; run from the repo root

if [ ! -d venv ]; then
    echo "[!] Python venv not found. Run ./bin/start_lab.sh first."
    exit 1
fi

for name in shellm beelzebub; do
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^$name$" || {
        echo "[!] '$name' isn't running. Start it: docker compose -f compose/$name.yml up -d --build"
        exit 1
    }
done

# shellcheck disable=SC1091
source venv/bin/activate
python3 src/redteam/benchmark.py "$@"
deactivate