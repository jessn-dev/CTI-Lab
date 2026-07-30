#!/bin/bash
# ==============================================================================
# Import the custom "CTI · Threat Overview" dashboard into the Wazuh dashboard.
# Saved objects (6 visualizations + 1 dashboard) live in
#   services/wazuh-config/wazuh_dashboard/cti-dashboard.ndjson
# Re-runnable — overwrite=true replaces existing copies.
# ==============================================================================
set -euo pipefail
cd "$(dirname "$0")/.."   # scripts live in bin/; run from the repo root

D="${WAZUH_DASHBOARD_URL:-https://localhost:8443}"
A="${WAZUH_DASHBOARD_AUTH:-admin:SecretPassword}"
NDJSON="services/wazuh-config/wazuh_dashboard/cti-dashboard.ndjson"

[ -f "$NDJSON" ] || { echo "[!] $NDJSON not found."; exit 1; }

echo "Waiting for the Wazuh dashboard API at $D ..."
ready=""
for i in $(seq 1 40); do
    if curl -sk -u "$A" -H 'osd-xsrf: true' "$D/api/saved_objects/_find?type=index-pattern&per_page=1" >/dev/null 2>&1; then
        ready=1; break
    fi
    sleep 5
done
[ -n "$ready" ] || { echo "[!] Dashboard API not reachable. Is the stack up + the dashboard finished initialising?"; exit 1; }

echo "Importing custom dashboard..."
curl -sk -u "$A" -X POST "$D/api/saved_objects/_import?overwrite=true" \
    -H 'osd-xsrf: true' --form file=@"$NDJSON" \
| python3 -c 'import sys,json
d=json.load(sys.stdin)
ok=d.get("success"); n=d.get("successCount")
print("[+] success="+str(ok)+"  imported="+str(n)+" objects")
for e in d.get("errors", []) or []:
    print("   error:", e.get("id"), e.get("error"))'

echo ""
echo "Open it:  $D  →  ☰ menu  →  Dashboards  →  'CTI · Threat Overview'"
