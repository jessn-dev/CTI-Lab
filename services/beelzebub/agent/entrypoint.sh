#!/bin/bash
# Enroll with the Wazuh manager, then run the agent so it forwards beelzebub's
# JSON event log. Kept separate from the beelzebub container (scratch image).
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
# Explicit agent name: this container shares beelzebub's network namespace, so
# its hostname is beelzebub's container id. Without -A the agent enrolls under
# that random id and the SIEM shows a mystery host instead of "beelzebub-agent".
AGENT_NAME="${WAZUH_AGENT_NAME:-beelzebub-agent}"

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
    echo "[bz-agent] enrolling as ${AGENT_NAME}..."
    /var/ossec/bin/agent-auth -m "${MANAGER}" -A "${AGENT_NAME}" || \
        echo "[bz-agent] WARN: enrollment failed; agentd will retry."
fi

# Re-apply the shared blocklist into beelzebub's netns (see active_defense.py).
BAN_DIR=/var/lib/defense-state
if [ -d "$BAN_DIR" ]; then
    for ip in $(ls "$BAN_DIR" 2>/dev/null); do
        case "$ip" in
            *[!0-9.:aAbBcCdDeEfF]*) continue ;;
        esac
        iptables -C INPUT -s "$ip" -j DROP 2>/dev/null \
            || iptables -A INPUT -s "$ip" -j DROP 2>/dev/null \
            && echo "[bz-agent] re-applied ban on $ip"
    done
fi

echo "[bz-agent] starting agent..."
/var/ossec/bin/wazuh-control start || echo "[bz-agent] WARN: start returned non-zero."

# Watchdog. PID 1 in this container is `tail`, not the agent, so when the agent
# restarts itself - which it does whenever the manager pushes shared config, e.g.
# a new Active Response - the daemons can go down and stay down while the
# container still looks healthy. Seen live: execd exited on a config push and the
# agent silently stopped executing Active Responses.
(
    while true; do
        sleep 30
        if ! /var/ossec/bin/wazuh-control status 2>/dev/null | grep -q "wazuh-agentd is running"; then
            echo "[bz-agent] agent is down; restarting it."
            /var/ossec/bin/wazuh-control start || true
        fi
    done
) &

# Stay in the foreground, surfacing the agent log.
exec tail -f /var/ossec/logs/ossec.log
