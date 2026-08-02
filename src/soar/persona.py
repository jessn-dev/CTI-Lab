#!/usr/bin/python3
"""
Persona - custom Wazuh Active Response script (Phase C-2 adaptive LLM surface).

The third member of the adaptive-engagement family. active_defense.py BANS a
noisy attacker, engage.py plants lures for a skilled one, and this script
publishes the attacker's *tier* so the LLM honeypot can change its face:

    100400 OPPORTUNIST -> shelLM serves a bare, boring cloud VM persona
    100401 SKILLED     -> shelLM serves a busy internal jump host

It writes one small file per source IP into a shared docker volume
(/var/lib/tier-state, mounted in both honeypot containers). shelLM's
run.sh reads it at session start and picks the personality (see
services/shelLM/run.sh + services/shelLM/personalities/).

Why a shared volume: a <location>local</location> AR runs on the agent that raised
the alert, which for snoopy-driven tiers is the static honeypot - not shelLM. A
file in a shared volume crosses the gap without needing <location>all</location>
or a hardcoded agent id. The LLM honeypot's commands feed the same two tier rules,
so the alert may instead land on shelLM's agent, which ships this script and mounts
the same volume - either way the tier ends up in one place.

NOTE: absolute shebang (/usr/bin/python3) + absolute paths - wazuh-execd runs
Active Response scripts with a minimal PATH (same constraint as active_defense.py).

Wazuh AR protocol (4.x): JSON message on stdin. `command == "add"` publishes the
tier; `command == "delete"` (timeout) retires it, so the attacker drops back to
the default persona on their next visit.
"""

import sys
import json
import os
import re
import time
import datetime

# Written by the agent; same log active_defense/engage use, so persona changes
# sit next to bans and lures in the active-responses stream.
LOG_FILE = "/var/ossec/logs/active-responses.log"

# Shared with the shelLM container (docker volume "tier-state").
TIER_DIR = "/var/lib/tier-state"

# Correlation rule -> tier name. Anything else is ignored.
# One tier pair covers every honeypot: both surfaces tag their category rules
# with the shared hp_recon/deep_attack groups and 100400/100401 correlate them
# per source IP, so this script runs on whichever agent raised the alert.
TIERS = {
    "100400": "OPPORTUNIST",
    "100401": "SKILLED",
}

# The IP becomes a filename, and it arrives from a decoded log line - so it is
# attacker-influenced. Only ever accept plain IPv4/IPv6 characters (no "/", no
# "..") before touching the filesystem.
IP_RE = re.compile(r"^[0-9a-fA-F.:]{3,45}$")


def log(message):
    """Append a timestamped line to the active-responses log (best effort)."""
    timestamp = datetime.datetime.now().isoformat()
    line = f"{timestamp} persona: {message}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        pass
    print(line, end="")


def tier_path(srcip):
    """Path of the state file for this IP, or None if the IP looks unsafe."""
    if not srcip or not IP_RE.match(srcip) or os.path.sep in srcip:
        return None
    return os.path.join(TIER_DIR, srcip)


def publish(srcip, tier):
    """Write '<TIER> <epoch>' for this IP. Never raise - AR must not crash."""
    path = tier_path(srcip)
    if not path:
        log(f"refusing to publish tier for suspicious srcip {srcip!r}")
        return False
    try:
        os.makedirs(TIER_DIR, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"{tier} {int(time.time())}\n")
        # shelLM reads this as an unprivileged forced command.
        os.chmod(path, 0o644)
        return True
    except OSError as exc:
        log(f"failed to publish tier for {srcip}: {exc}")
        return False


def retire(srcip):
    """Drop the state file so the next session gets the default persona."""
    path = tier_path(srcip)
    if not path:
        return False
    try:
        os.remove(path)
        return True
    except FileNotFoundError:
        return False
    except OSError as exc:
        log(f"failed to retire tier for {srcip}: {exc}")
        return False


def main():
    # readline(), not read(): execd keeps the stdin pipe open (see active_defense).
    raw = sys.stdin.readline().strip()
    if not raw and len(sys.argv) > 1:
        raw = sys.argv[1].strip()
    if not raw:
        log("no AR input received")
        sys.exit(1)

    try:
        msg = json.loads(raw)
    except json.JSONDecodeError:
        log(f"invalid AR JSON: {raw[:200]}")
        sys.exit(1)

    command = msg.get("command", "add")
    alert = (msg.get("parameters") or {}).get("alert") or {}
    rule_id = str((alert.get("rule") or {}).get("id", ""))
    srcip = (alert.get("data") or {}).get("srcip", "")

    tier = TIERS.get(rule_id)
    if not tier:
        log(f"rule {rule_id or '?'} is not a tier rule; nothing to do")
        return

    if not srcip:
        # Command events carry the SSH client IP (snoopy logs SSH_CLIENT), but a
        # tier alert built from an event without one leaves us nothing to key on.
        log(f"tier {tier} with no srcip in the alert; nothing to publish")
        return

    if command == "add":
        if publish(srcip, tier):
            log(f"tier {tier} published for {srcip} - shelLM will serve the "
                f"matching persona on the next session")
    elif command == "delete":
        if retire(srcip):
            log(f"tier {tier} retired for {srcip} (back to the default persona)")
        else:
            log(f"no tier state to retire for {srcip}")
    else:
        log(f"unknown command '{command}'")


if __name__ == "__main__":
    main()
