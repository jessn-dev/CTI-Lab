#!/usr/bin/python3
"""
Active Defense - custom Wazuh Active Response script (SOAR).

NOTE: absolute shebang (/usr/bin/python3), not /usr/bin/env python3. Wazuh's
wazuh-execd spawns Active Response scripts with a minimal PATH, so `env` cannot
find python3 and the script would never start. For the same reason every
external binary below (iptables) is called by absolute path.

Ships inside the linux-honeypot agent image at
    /var/ossec/active-response/bin/active_defense.py
and is invoked by the Wazuh manager when an SSH brute-force rule fires
(see the <active-response> block in config/wazuh_cluster/wazuh_manager.conf).

Wazuh Active Response protocol (4.x): the manager sends a JSON message on
stdin. On `command == "add"` we ban the attacker's source IP with iptables;
on `command == "delete"` (fired when the <timeout> expires) we remove the ban.
Every action is appended to the standard Wazuh active-responses log so it shows
up in the SIEM.

MITRE D3FEND: D3-NTF (Network Traffic Filtering).
"""

import sys
import json
import os
import re
import time
import datetime
import subprocess

# Written by the agent; tailed back into Wazuh as an alert source.
LOG_FILE = "/var/ossec/logs/active-responses.log"
# Absolute path — execd runs us with a minimal PATH (see module docstring).
IPTABLES = "/usr/sbin/iptables"

# Shared blocklist (docker volume "defense-state"), mounted in every honeypot.
# A ban is a decision about an ATTACKER, not about one container: the tripwire
# fires on whichever honeypot the attacker took the bait on, and Wazuh's
# <location>all</location> pushes the ban to every agent that is up. This file is
# the other half - a honeypot that starts (or restarts) later replays the list at
# boot, so disengagement survives a container recreate.
BAN_DIR = "/var/lib/defense-state"

# The IP becomes a filename and comes from a decoded log line, so it is
# attacker-influenced: accept only plain IPv4/IPv6 characters.
IP_RE = re.compile(r"^[0-9a-fA-F.:]{3,45}$")


def log(message):
    """Append a timestamped line to the active-responses log (best effort)."""
    timestamp = datetime.datetime.now().isoformat()
    line = f"{timestamp} active_defense: {message}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        pass
    # Also emit to stdout so it is captured in the AR debug log.
    print(line, end="")


def run(cmd):
    """Run a command, return (rc, combined_output)."""
    try:
        proc = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15
        )
        return proc.returncode, proc.stdout.decode(errors="ignore").strip()
    except Exception as exc:  # never let AR crash the agent
        return 1, str(exc)


def _ban_record(ip):
    """Path of the shared blocklist entry, or None if the IP looks unsafe."""
    if not ip or not IP_RE.match(ip) or os.path.sep in ip:
        return None
    return os.path.join(BAN_DIR, ip)


def record_ban(ip):
    """Add the IP to the shared blocklist (best effort - never fatal)."""
    path = _ban_record(ip)
    if not path:
        log(f"refusing to record suspicious srcip {ip!r}")
        return
    try:
        os.makedirs(BAN_DIR, exist_ok=True)
        with open(path, "w") as f:
            f.write(f"{int(time.time())}\n")
    except OSError as exc:
        log(f"could not record ban for {ip}: {exc}")


def forget_ban(ip):
    """Drop the IP from the shared blocklist when the ban expires."""
    path = _ban_record(ip)
    if not path:
        return
    try:
        os.remove(path)
    except FileNotFoundError:
        pass
    except OSError as exc:
        log(f"could not clear ban record for {ip}: {exc}")


def _rule_exists(ip):
    rc, _ = run([IPTABLES, "-C", "INPUT", "-s", ip, "-j", "DROP"])
    return rc == 0


def ban_ip(ip):
    """Drop NEW traffic from the malicious IP with iptables.

    Uses -A (append), not -I (insert), so the DROP lands AFTER the
    ESTABLISHED,RELATED accept rule the honeypot installs at boot. Result: an
    already-established attacker session keeps working, but new connections from
    the banned IP are dropped - matching a real firewall block that doesn't tear
    down live sessions.
    """
    if _rule_exists(ip):
        log(f"IP {ip} already banned, skipping")
        return
    rc, out = run([IPTABLES, "-A", "INPUT", "-s", ip, "-j", "DROP"])
    record_ban(ip)
    if rc == 0:
        log(f"BANNED malicious IP -> {ip} (iptables DROP)")
    else:
        # NET_ADMIN missing or iptables unavailable: still record the decision.
        log(f"WANTED-BAN {ip} but iptables failed ({out}); logged only")


def unban_ip(ip):
    """Remove the ban when the Wazuh timeout expires."""
    rc, out = run([IPTABLES, "-D", "INPUT", "-s", ip, "-j", "DROP"])
    forget_ban(ip)
    if rc == 0:
        log(f"UNBANNED {ip} (timeout expired)")
    else:
        log(f"UNBAN {ip} failed or rule absent ({out})")


def extract_ip(msg):
    """Pull the source IP out of the AR message (schema-tolerant)."""
    params = msg.get("parameters", {})
    alert = params.get("alert", {})
    data = alert.get("data", {})
    # Preferred location, then a couple of fallbacks seen across rule types.
    return data.get("srcip") or alert.get("srcip") or msg.get("srcip")


def main():
    # readline(), NOT read(): Wazuh execd sends the AR message as a single JSON
    # line but keeps the stdin pipe open, so read() (which waits for EOF) blocks
    # until execd kills the script. readline() returns as soon as the newline
    # arrives. (A manual `printf | script` test works with read() only because
    # the pipe closes - which masked this bug during development.)
    raw = sys.stdin.readline().strip()

    # Fallback: some setups pass the JSON as an argv instead of stdin.
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
    ip = extract_ip(msg)

    if not ip:
        log("no source IP found in alert; nothing to do")
        sys.exit(0)

    if command == "add":
        ban_ip(ip)
    elif command == "delete":
        unban_ip(ip)
    else:
        log(f"unknown command '{command}' for {ip}")


if __name__ == "__main__":
    main()
