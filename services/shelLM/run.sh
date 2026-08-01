#!/bin/bash
# ForceCommand target: sshd runs this for EVERY login (see Dockerfile).
# 1) look up the attacker's tier, 2) log a session-start event for the SIEM,
# 3) drop the attacker into the shelLM LLM shell (a readline chatbot -- needs the
# session pty sshd gives) wearing the persona that matches the tier.
#
# sshd does not pass the container's environment to a forced command, so the
# model/personality come from /opt/shelLM/.runenv, written by entrypoint.sh.
[ -f /opt/shelLM/.runenv ] && . /opt/shelLM/.runenv

# SSH_CONNECTION = "<client_ip> <client_port> <server_ip> <server_port>"
SRC_IP="${SSH_CONNECTION%% *}"
TS="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

# --- Phase C-2: adaptive persona -------------------------------------------
# src/soar/persona.py (Active Response on the static honeypot) publishes the
# attacker's tier into the shared "tier-state" volume, one file per source IP:
#   <TIER> <epoch>
# A tier older than SHELLM_TIER_TTL is ignored, so a stale classification can't
# pin an IP to the rich persona forever.
TIER_DIR="${SHELLM_TIER_DIR:-/var/lib/tier-state}"
TIER_TTL="${SHELLM_TIER_TTL:-3600}"
TIER="NONE"

if [ -n "$SRC_IP" ] && [ -r "$TIER_DIR/$SRC_IP" ]; then
    read -r found_tier found_ts _ < "$TIER_DIR/$SRC_IP"
    age=$(( $(date +%s) - ${found_ts:-0} ))
    if [ -n "$found_tier" ] && [ "$age" -ge 0 ] && [ "$age" -le "$TIER_TTL" ]; then
        TIER="$found_tier"
    fi
fi

case "$TIER" in
    SKILLED)     PERSONALITY="Tier_skilled" ;;      # busy internal jump host
    OPPORTUNIST) PERSONALITY="Tier_opportunist" ;;  # bare, boring cloud VM
    *)           PERSONALITY="${SHELLM_PERSONALITY:-Eman_v1}" ;;
esac

printf '{"honeypot":"shelLM","event":"session_start","protocol":"SSH","srcip":"%s","user":"%s","tier":"%s","persona":"%s","time":"%s"}\n' \
    "${SRC_IP:-unknown}" "${USER:-root}" "$TIER" "$PERSONALITY" "$TS" \
    >> /var/log/shellm.json 2>/dev/null

# shelLM replays the previous session's transcript so the fake box stays
# consistent across logins -- its whole point. That only holds while the box is
# the SAME box: when the persona changes, the old transcript describes a
# different machine, so wipe the history (--cleaned) exactly on a switch and
# keep it otherwise.
LAST_PERSONA_FILE=/opt/shelLM/.last_persona
CLEANED=""
if [ "$(cat "$LAST_PERSONA_FILE" 2>/dev/null)" != "$PERSONALITY" ]; then
    CLEANED="--cleaned"
    printf '%s\n' "$PERSONALITY" > "$LAST_PERSONA_FILE" 2>/dev/null
fi

# Session context for the per-command logger patched into LinuxSSHbot.py
# (services/shelLM/patch_command_log.py) - it has no other way to know who is
# typing, since shelLM itself never sees the connection.
export SHELLM_SRCIP="${SRC_IP:-unknown}"
export SHELLM_TIER="$TIER"
export SHELLM_PERSONA="$PERSONALITY"

cd /opt/shelLM/shelLMv2 || exit 1
exec /opt/shelLM/venv/bin/python3 LinuxSSHbot.py \
    --provider ollama \
    --model "${SHELLM_MODEL:-llama3.2:3b}" \
    --personality "$PERSONALITY" \
    $CLEANED
