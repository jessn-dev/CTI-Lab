#!/bin/bash
# ForceCommand target: sshd runs this for EVERY login (see Dockerfile).
# 1) log a session-start event for the SIEM, 2) drop the attacker straight into
# the shelLM LLM shell (a readline chatbot -- needs the session pty sshd gives).
#
# sshd does not pass the container's environment to a forced command, so the
# model/personality come from /opt/shelLM/.runenv, written by entrypoint.sh.
[ -f /opt/shelLM/.runenv ] && . /opt/shelLM/.runenv

# SSH_CONNECTION = "<client_ip> <client_port> <server_ip> <server_port>"
SRC_IP="${SSH_CONNECTION%% *}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
printf '{"honeypot":"shelLM","event":"session_start","protocol":"SSH","srcip":"%s","user":"%s","time":"%s"}\n' \
    "${SRC_IP:-unknown}" "${USER:-root}" "$TS" >> /var/log/shellm.json 2>/dev/null

cd /opt/shelLM/shelLMv2 || exit 1
exec /opt/shelLM/venv/bin/python3 LinuxSSHbot.py \
    --provider ollama \
    --model "${SHELLM_MODEL:-llama3.2:3b}" \
    --personality "${SHELLM_PERSONALITY:-Eman_v1}"
