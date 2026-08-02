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
# Retry: on a rebuild the manager may still hold this name, and a container that
# starts unenrolled looks healthy while forwarding NOTHING - an attack run then
# produces zero alerts with no obvious cause. Fail loudly instead.
if [ ! -s /var/ossec/etc/client.keys ]; then
    for attempt in 1 2 3; do
        echo "[honeypot] enrolling agent with ${MANAGER} (attempt ${attempt}/3)..."
        /var/ossec/bin/agent-auth -m "${MANAGER}" && break
        sleep 10
    done
fi

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[honeypot] ================================================================"
    echo "[honeypot] ERROR: NOT ENROLLED - this container will forward no events."
    echo "[honeypot] Usually a stale record with the same name on the manager."
    echo "[honeypot]   docker exec wazuh.manager /var/ossec/bin/agent_control -l"
    echo "[honeypot]   docker exec wazuh.manager /var/ossec/bin/manage_agents -r <id>"
    echo "[honeypot] then restart this container."
    echo "[honeypot] ================================================================"
fi

echo "[honeypot] starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || echo "[honeypot] WARN: wazuh-control start returned non-zero."

# Command auditing (Phase C1): activate snoopy's LD_PRELOAD now, AFTER the agent
# is up, so it logs attacker commands (sshd children) rather than our own startup.
# Pre-create the log so the agent's logcollector can open it at boot.
echo "[honeypot] enabling snoopy command auditing..."
touch /var/log/snoopy.log
SNOOPY_LIB="$(dpkg -L snoopy 2>/dev/null | grep -E 'libsnoopy\.so$' | head -1)"
if [ -n "$SNOOPY_LIB" ]; then
    echo "$SNOOPY_LIB" > /etc/ld.so.preload
    echo "[honeypot] snoopy active ($SNOOPY_LIB) -> /var/log/snoopy.log"
else
    echo "[honeypot] WARN: libsnoopy.so not found; command auditing disabled."
fi

echo "[honeypot] starting sshd on :22 (root:toor bait)..."
# NOTE: no -e flag. -e sends sshd logs to stderr instead of syslog; we need
# sshd to log via syslog so rsyslog writes /var/log/auth.log, which the Wazuh
# agent reads to detect the brute force. Logs still visible in the container
# via /var/log/auth.log (and journald).
exec /usr/sbin/sshd -D
