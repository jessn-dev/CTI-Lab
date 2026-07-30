#!/bin/bash
# ==============================================================================
# Threat Intelligence Lab - startup
# 1. generate Wazuh TLS certs (once)  2. tune host  3. bring the stack up
# 4. run the Python adversary simulation once the honeypot agent is connected
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."   # scripts live in bin/; run from the repo root

# ---- pick the right compose command (v2 plugin vs legacy v1) ----------------
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    echo "[!] Docker Compose not found. Install Docker Desktop and retry."
    exit 1
fi

echo "===================================================="
echo "  Booting Threat Intelligence Lab Infrastructure"
echo "===================================================="

# ---- [1/5] TLS certificates -------------------------------------------------
if [ ! -f services/wazuh-config/wazuh_indexer_ssl_certs/root-ca.pem ]; then
    echo "[1/5] Generating Wazuh TLS certificates..."
    $DC -f compose/generate-certs.yml run --rm generator
else
    echo "[1/5] TLS certificates already present, skipping."
fi

# ---- [2/5] Host tuning (indexer needs a high vm.max_map_count) --------------
echo "[2/5] Ensuring vm.max_map_count >= 262144..."
if [ "$(uname)" = "Linux" ]; then
    sudo sysctl -w vm.max_map_count=262144 || \
        echo "    (could not set sysctl - set it manually if the indexer fails)"
else
    # On Docker Desktop (macOS/Windows) the setting lives in the LinuxKit VM.
    docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144 || \
        echo "    (could not set sysctl in the Docker VM - continue anyway)"
fi

# ---- [3/5] Bring up SIEM + honeypot -----------------------------------------
# Core lab only (SIEM + static honeypot). The LLM honeypots (beelzebub, shelLM)
# need the native Ollama running, so they stay opt-in:
#   docker compose -f compose/beelzebub.yml up -d
#   docker compose -f compose/shellm.yml   up -d --build
echo "[3/5] Starting Wazuh SIEM + honeypot (this builds the honeypot image)..."
$DC -f compose/wazuh.yml -f compose/honeypot.yml up -d --build

echo "      Waiting for the indexer/manager to initialise (up to ~90s)..."
sleep 60

# ---- [4/5] Python environment -----------------------------------------------
echo "[4/5] Preparing Python virtual environment..."
if [ ! -d venv ]; then python3 -m venv venv; fi
# shellcheck disable=SC1091
source venv/bin/activate
pip install -q --disable-pip-version-check -r requirements.txt

# ---- [5/5] Wait for the honeypot agent, then attack -------------------------
echo "[5/5] Waiting for the honeypot SSH service on 127.0.0.1:2222..."
for i in $(seq 1 30); do
    if nc -z 127.0.0.1 2222 2>/dev/null; then break; fi
    sleep 3
done

# Wait for the honeypot's Wazuh agent to actually connect, so the brute-force
# events are ingested rather than fired into a disconnected agent.
echo "      Waiting for the honeypot agent to enroll + connect to Wazuh..."
for i in $(seq 1 30); do
    if docker exec wazuh.manager /var/ossec/bin/agent_control -l 2>/dev/null \
        | grep -qi "linux-honeypot.*Active"; then
        echo "      Agent connected."
        break
    fi
    sleep 5
done

deactivate

# Best-effort: import the custom "CTI · Threat Overview" dashboard once the
# dashboard API is ready. Runs in the background so it never blocks startup.
( bin/import-dashboard.sh >/dev/null 2>&1 & ) 2>/dev/null || true

echo ""
echo "===================================================="
echo "  ✅ Lab is LIVE and waiting."
echo "===================================================="
echo "  Wazuh dashboard : https://localhost:8443    (admin / SecretPassword)"
echo "  SSH honeypot    : ssh root@localhost -p 2222 (password: toor)"
echo "  Portfolio site  : open docs/index.html"
echo ""
echo "  ── WATCH THE ATTACK LIVE ──────────────────────────"
echo "  1. Open the dashboard above and log in (give it ~1-2 min"
echo "     on first boot while the security index builds)."
echo "  2. Go to  Threat Hunting  →  Events / Security Alerts,"
echo "     and leave it open."
echo "  3. In another terminal, launch the adversary simulation:"
echo ""
echo "         ./bin/attack.sh"
echo ""
echo "  4. Watch the kill chain appear in real time:"
echo "       - SSH brute force  (rule 5763, level 10)"
echo "       - Active Response ban of the attacker IP"
echo "       - FIM 'new file' on /tmp/eicar.com.txt + VirusTotal verdict"
echo ""
echo "  Custom dashboard 'CTI · Threat Overview' auto-imports once the"
echo "  dashboard is ready (or run ./bin/import-dashboard.sh). Find it under"
echo "  ☰ menu → Dashboards. Terminal-only? Use ./bin/logs.sh"
echo ""
echo "  Generate an AI threat report afterwards:  ./bin/report.sh"
echo "  Stop everything:                          ./bin/stop_lab.sh"
echo "===================================================="
