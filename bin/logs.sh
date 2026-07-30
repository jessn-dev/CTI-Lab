#!/bin/bash
# ==============================================================================
# View the SIEM from a terminal — no dashboard needed.
#
#   ./bin/logs.sh            live alert stream (human-readable text)
#   ./bin/logs.sh json       live alert stream, key fields only (level/id/srcip)
#   ./bin/logs.sh ar         Active-Response bans (on the honeypot)
#   ./bin/logs.sh vt         VirusTotal integration log (on the manager)
#   ./bin/logs.sh auth       honeypot SSH auth.log (raw login attempts)
#   ./bin/logs.sh agents     enrolled agents + connection status (snapshot)
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."   # scripts live in bin/; run from the repo root

MODE="${1:-alerts}"

need() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^$1$" || {
        echo "[!] Container '$1' isn't running. Start the lab: ./bin/start_lab.sh"
        exit 1
    }
}

case "$MODE" in
    alerts)
        need wazuh.manager
        echo "── live alerts (Ctrl-C to stop) ─ /var/ossec/logs/alerts/alerts.log ──"
        docker exec -it wazuh.manager tail -f /var/ossec/logs/alerts/alerts.log
        ;;
    json)
        need wazuh.manager
        echo "── live alerts: level | rule | description | srcip (Ctrl-C to stop) ──"
        docker exec wazuh.manager tail -f /var/ossec/logs/alerts/alerts.json \
        | python3 -c '
import sys, json
for line in sys.stdin:
    try: a = json.loads(line)
    except ValueError: continue
    r = a.get("rule", {}) or {}
    ip = (a.get("data") or {}).get("srcip", "-")
    lvl = r.get("level", "?")
    rid = r.get("id", "?")
    desc = r.get("description", "")
    mark = "!!" if isinstance(lvl, int) and lvl >= 10 else "  "
    print(f"{mark} lvl={lvl:<2} rule={rid:<6} src={ip:<15} {desc}")
    sys.stdout.flush()'
        ;;
    ar)
        need linux-honeypot
        echo "── Active-Response bans (Ctrl-C to stop) ──"
        docker exec -it linux-honeypot tail -f /var/ossec/logs/active-responses.log
        ;;
    vt)
        need wazuh.manager
        echo "── VirusTotal integration (Ctrl-C to stop) ──"
        docker exec -it wazuh.manager tail -f /var/ossec/logs/integrations.log
        ;;
    auth)
        need linux-honeypot
        echo "── honeypot /var/log/auth.log (Ctrl-C to stop) ──"
        docker exec -it linux-honeypot tail -f /var/log/auth.log
        ;;
    agents)
        need wazuh.manager
        docker exec wazuh.manager /var/ossec/bin/agent_control -l
        ;;
    -h|--help|help)
        sed -n '3,13p' "$0"
        ;;
    *)
        echo "[!] Unknown mode '$MODE'. Try: alerts | json | ar | vt | auth | agents"
        exit 1
        ;;
esac
