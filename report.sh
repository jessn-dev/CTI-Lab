#!/bin/bash
# ==============================================================================
# Generate an AI (Gemini) MITRE ATT&CK threat report from the Wazuh detections
# this run produced. Offline analysis - reads the alerts, never touches the
# attack path. Needs GEMINI_API_KEY in .env (free key: https://aistudio.google.com).
# Pass-through args are forwarded (e.g. --input path/to/alerts.json).
# ==============================================================================
set -e
cd "$(dirname "$0")"

if [ ! -d venv ]; then
    echo "[!] Python venv not found. Run ./start_lab.sh first."
    exit 1
fi

# shellcheck disable=SC1091
source venv/bin/activate
python3 scripts/threat_report.py "$@"
deactivate
