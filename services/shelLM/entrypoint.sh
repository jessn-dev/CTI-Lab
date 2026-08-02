#!/bin/bash
# shelLM honeypot entrypoint: write shelLM config, start rsyslog (auth.log),
# enroll + start the Wazuh agent, then run sshd in the foreground. Every SSH
# login is forced into the shelLM LLM shell (see run.sh / Dockerfile).
set -e

MANAGER="${WAZUH_MANAGER:-wazuh.manager}"
OLLAMA_URL="${OLLAMA_BASE_URL:-http://host.docker.internal:11434}"

# shelLM reads OLLAMA_BASE_URL from a .env TWO dirs above LinuxSSHbot.py. The
# script lives at /opt/shelLM/shelLMv2/LinuxSSHbot.py, so ../../ resolves to
# /opt -> the .env must be /opt/.env (NOT /opt/shelLM/.env). run.sh reads
# .runenv for model/personality, since sshd does not forward the container env
# to a ForceCommand.
echo "[shellm] writing shelLM config (Ollama at ${OLLAMA_URL})..."
printf 'OLLAMA_BASE_URL=%s\n' "${OLLAMA_URL}" > /opt/.env
{
    printf 'SHELLM_MODEL=%s\n'       "${SHELLM_MODEL:-llama3.2:3b}"
    printf 'SHELLM_PERSONALITY=%s\n' "${SHELLM_PERSONALITY:-Eman_v1}"
} > /opt/shelLM/.runenv
mkdir -p /opt/shelLM/shelLMv2/logs

# Same baseline as the static honeypot: accept established traffic FIRST so the
# tripwire ban (appended, not inserted) cuts new connections without killing the
# session that tripped it.
echo "[shellm] installing baseline firewall (keeps live sessions alive)..."
iptables -C INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT 2>/dev/null \
    || echo "[shellm] WARN: could not set conntrack accept rule (no NET_ADMIN?)."

echo "[shellm] starting rsyslog (populates /var/log/auth.log)..."
rsyslogd

# Pre-create the files logcollector opens at startup; if absent, the initial
# open fails and the agent never re-attaches (same gotcha as the static
# honeypot's auth.log).
touch /var/log/auth.log
chown syslog:adm /var/log/auth.log 2>/dev/null || true
chmod 640 /var/log/auth.log
touch /var/log/shellm.json

echo "[shellm] waiting for Wazuh manager ${MANAGER}:1515 ..."
for i in $(seq 1 60); do
    if (echo > /dev/tcp/"${MANAGER}"/1515) >/dev/null 2>&1; then
        echo "[shellm] manager reachable."
        break
    fi
    sleep 5
done

# Retry, then fail loudly: an unenrolled container still answers SSH, so a silent
# failure here looks like "shelLM works but never reaches the SIEM".
if [ ! -s /var/ossec/etc/client.keys ]; then
    for attempt in 1 2 3; do
        echo "[shellm] enrolling agent with ${MANAGER} (attempt ${attempt}/3)..."
        /var/ossec/bin/agent-auth -m "${MANAGER}" && break
        sleep 10
    done
fi

if [ ! -s /var/ossec/etc/client.keys ]; then
    echo "[shellm] ================================================================"
    echo "[shellm] ERROR: NOT ENROLLED - sessions will not reach the SIEM."
    echo "[shellm] Check for a stale 'shellm' record on the manager:"
    echo "[shellm]   docker exec wazuh.manager /var/ossec/bin/agent_control -l"
    echo "[shellm]   docker exec wazuh.manager /var/ossec/bin/manage_agents -r <id>"
    echo "[shellm] ================================================================"
fi

echo "[shellm] starting Wazuh agent..."
/var/ossec/bin/wazuh-control start || echo "[shellm] WARN: wazuh-control start returned non-zero."

echo "[shellm] starting sshd on :22 (root:toor -> shelLM LLM shell)..."
# No -e: sshd must log via syslog so rsyslog writes /var/log/auth.log, which the
# agent reads to detect the login/brute force.
exec /usr/sbin/sshd -D
