#!/bin/bash
# Honeypot entrypoint: start rsyslog (auth.log), enroll + start the Wazuh
# agent, then run sshd in the foreground so the container stays alive.
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"

echo "[honeypot] installing baseline firewall (keeps live sessions alive)..."
# Accept already-established/related traffic FIRST, so when Active Response
# appends a DROP for the attacker's IP, an existing foothold session survives
# while new connections from that IP are blocked (see active_defense.py).
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || echo "[honeypot] WARN: could not set conntrack accept rule."

echo "[honeypot] starting rsyslog (populates /var/log/auth.log)..."
rsyslogd

# Pre-create auth.log so the Wazuh agent's logcollector can open it at startup.
# rsyslog only creates the file on the first auth event, which is too late -
# logcollector fails the initial open and never re-attaches, so SSH brute-force
# events would never be ingested.
touch /var/log/auth.log
chown syslog:adm /var/log/auth.log 2>/dev/null || true
chmod 640 /var/log/auth.log

# Point the agent at the manager and wait for the enrollment port (1515).
echo "[honeypot] waiting for Wazuh manager ${MANAGER}:1515 ..."
for i in $(seq 1 60); do
    if (echo > /dev/tcp/"${MANAGER}"/1515) >/dev/null 2>&1; then
        echo "[honeypot] manager reachable."
        break
    fi
    sleep 5
done

# Enroll (idempotent: skips if client.keys already present) and start agent.
if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[honeypot] enrolling agent with ${MANAGER}..."
    /var/ossec/bin/agent-auth -m "${MANAGER}" || \
        echo "[honeypot] WARN: enrollment failed, agent will retry via auto-enrollment."
fi

echo "[honeypot] starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || echo "[honeypot] WARN: wazuh-control start returned non-zero."

echo "[honeypot] starting sshd on :22 (root:toor bait)..."
# NOTE: no -e flag. -e sends sshd logs to stderr instead of syslog; we need
# sshd to log via syslog so rsyslog writes /var/log/auth.log, which the Wazuh
# agent reads to detect the brute force. Logs still visible in the container
# via /var/log/auth.log (and journald).
exec /usr/sbin/sshd -D
