#!/bin/bash
# Enroll with the Wazuh manager, then run the agent so it forwards beelzebub's
# JSON event log. Kept separate from the beelzebub container (scratch image).
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

# Pre-create the log file so logcollector can open it at startup even before
# beelzebub has written its first event (an absent file otherwise fails the
# open and never re-attaches).
[ -f /logs/beelzebub.json ] || touch /logs/beelzebub.json 2>/dev/null || true

echo "[bz-agent] waiting for Wazuh manager ${MANAGER}:1515 ..."
for i in $(seq 1 60); do
    if (echo > /dev/tcp/"${MANAGER}"/1515) >/dev/null 2>&1; then
        echo "[bz-agent] manager reachable."; break
    fi
    sleep 5
done

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[bz-agent] enrolling..."
    /var/ossec/bin/agent-auth -m "${MANAGER}" || \
        echo "[bz-agent] WARN: enrollment failed; agentd will retry."
fi

echo "[bz-agent] starting agent..."
/var/ossec/bin/wazuh-control start || echo "[bz-agent] WARN: start returned non-zero."

# Stay in the foreground, surfacing the agent log.
exec tail -f /var/ossec/logs/ossec.log
