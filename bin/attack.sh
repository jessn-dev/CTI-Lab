#!/bin/bash
# ==============================================================================
# Launch the adversary simulation against the honeypot.
# Run this AFTER ./start_lab.sh, with the Wazuh dashboard open, so you can watch
# the Cyber Kill Chain and the automated responses appear in real time.
# ==============================================================================
set -e
cd "$(dirname "$0")/.."   # scripts live in bin/; run from the repo root

if [ ! -d venv ]; then
    echo "[!] Python venv not found. Run ./bin/start_lab.sh first."
    exit 1
fi

if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^linux-honeypot$'; then
    echo "[!] Honeypot isn't running. Start the lab first: ./bin/start_lab.sh"
    exit 1
fi

# Clear any lingering Active-Response ban from a previous run so this run isn't
# blocked before it starts. The 600s iptables DROP on the attacker IP survives
# between runs; without this, re-running attack.sh within 10 min fails at the
# brute-force burst with "Error reading SSH protocol banner". We flush INPUT and
# restore only the baseline ESTABLISHED,RELATED accept rule.
echo "[*] Clearing any stale Active-Response ban on the honeypot..."
docker exec linux-honeypot sh -c \
    "iptables -F INPUT 2>/dev/null; \
     iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null; \
     : > /var/ossec/logs/active-responses.log 2>/dev/null; \
     rm -f /tmp/eicar.com.txt 2>/dev/null" 2>/dev/null || true

# shellcheck disable=SC1091
source venv/bin/activate
# Pass through args, e.g. --profile skilled|noise (Phase C adaptive-engagement demo).
python3 src/redteam/simulate_attacks.py "$@"
deactivate

echo ""
echo "Now check the Wazuh dashboard (https://localhost:8443) — Threat Hunting →"
echo "Security Alerts — for the brute force (5763), the Active Response ban, and"
echo "the FIM + VirusTotal malware verdict. Generate a report with: ./bin/report.sh"
