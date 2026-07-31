#!/usr/bin/python3
"""
Engage - custom Wazuh Active Response script (Phase C adaptive engagement).

The counterpart to active_defense.py. Where active_defense BANS a noisy attacker,
this ENGAGES a skilled one: when the manager classifies a session as tier SKILLED
(correlation rule 100401), it plants believable-but-fake lures on the honeypot to
keep the attacker interested and to bait a high-signal action. It deliberately
does NOT ban - the whole point is to keep a skilled attacker engaged long enough
to harvest more TTPs. Disengagement/banning is handled separately (Phase C5).

The lures are decoys only: an SSH private key, a DB backup, and a credentials
file - all obviously enticing, all fake, zero real value. When the attacker reads
or exfiltrates one (e.g. `cat /root/.ssh/id_rsa`), snoopy logs the command and the
tripwire rule (100402) fires - the loudest signal in the lab that they took the
bait.

NOTE: absolute shebang (/usr/bin/python3) + absolute paths - wazuh-execd runs
Active Response scripts with a minimal PATH (same constraint as active_defense.py).

Wazuh AR protocol (4.x): JSON message on stdin. On `command == "add"` we plant the
lures; on `command == "delete"` (timeout) we leave them in place (a tripwire can
still fire later) and just log the window close.
"""

import sys
import json
import os
import datetime

# Written by the agent; same log active_defense uses, so engage actions sit next
# to bans in the active-responses stream.
LOG_FILE = "/var/ossec/logs/active-responses.log"

# Decoy files planted on a SKILLED classification. Paths an attacker checks early.
# Content is deliberately fake - tempting shape, no real secret.
LURES = {
    "/root/.ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gt\n"
        "ZWQyNTUxOQAAACDECOY0000FAKEKEY0000NOTAREALPRIVATEKEY0000DECOY00000AAA\n"
        "AAAJhESITROPHONEYP0TDECOYKEYDONOTUSE0000000000000000000000000000000000\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    "/root/backup_db.sql": (
        "-- MySQL dump 10.13  Distrib 8.0.32\n"
        "-- Host: db-prod-01    Database: appdb\n"
        "INSERT INTO users (id,email,role,pw_hash) VALUES\n"
        "  (1,'admin@corp.local','superadmin','$2y$10$FAKEbcryptHASHnotReal000000000000000000000000'),\n"
        "  (2,'svc_backup@corp.local','service','$2y$10$FAKEbcryptHASHnotReal111111111111111111111111');\n"
        "-- connection: mysql://svc_backup:H0NEYtrap!fake@db-prod-01:3306/appdb\n"
    ),
    "/root/credentials.txt": (
        "# infra creds (rotate quarterly)\n"
        "prod-db     svc_backup / H0NEYtrap!fake\n"
        "aws         AKIAFAKE0000DECOY000 / fakeSecretKeyDECOYnotReal00000000000000\n"
        "jump-host   ops@10.10.10.9  (key: ~/.ssh/id_rsa)\n"
    ),
}


def log(message):
    """Append a timestamped line to the active-responses log (best effort)."""
    timestamp = datetime.datetime.now().isoformat()
    line = f"{timestamp} engage: {message}\n"
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line)
    except OSError:
        pass
    print(line, end="")


def plant_lures():
    """Write the decoy files (idempotent). Never raise - AR must not crash."""
    planted = 0
    for path, content in LURES.items():
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            # Don't clobber a lure an attacker may already be looking at.
            if not os.path.exists(path):
                with open(path, "w") as f:
                    f.write(content)
                # Private key should look real: tight perms.
                if path.endswith("id_rsa"):
                    os.chmod(path, 0o600)
                planted += 1
        except OSError as exc:
            log(f"failed to plant {path}: {exc}")
    return planted


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

    if command == "add":
        n = plant_lures()
        if n:
            log(f"ENGAGE (tier SKILLED): planted {n} lure(s); NOT banning - "
                f"holding the attacker to harvest TTPs")
        else:
            log("ENGAGE: lures already present; no change")
    elif command == "delete":
        # Leave the lures in place so a later read still trips the tripwire.
        log("engage window expired (lures left in place)")
    else:
        log(f"unknown command '{command}'")


if __name__ == "__main__":
    main()
