#!/bin/bash
# ==============================================================================
# Launch the adversary simulation against the honeypot.
# Run this AFTER ./start_lab.sh, with the Wazuh dashboard open, so you can watch
# the Cyber Kill Chain and the automated responses appear in real time.
# ==============================================================================
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
    echo "[!] Python venv not found. Run ./start_lab.sh first."
    exit 1
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^linux-honeypot$'; then
    echo "[!] Honeypot isn't running. Start the lab first: ./start_lab.sh"
    exit 1
fi

# shellcheck disable=SC1091
source venv/bin/activate
python3 scripts/simulate_attacks.py
deactivate

echo ""
echo "Now check the Wazuh dashboard (https://localhost:8443) — Threat Hunting →"
echo "Security Alerts — for the brute force (5763), the Active Response ban, and"
echo "the FIM + VirusTotal malware verdict. Generate a report with: ./report.sh"
