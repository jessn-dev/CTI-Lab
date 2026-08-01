#!/usr/bin/env python3
"""
Build-time patch: log every command an attacker types into shelLM.

shelLM keeps its own transcripts (shelLMv2/logs/history.txt, command_history.txt)
but they are readline/dialog artifacts - no timestamps, no source IP, flushed at
session end - so they are useless as a SIEM feed. Until now only the *session
start* reached Wazuh (run.sh -> rule 100311), which meant everything the attacker
actually did inside the LLM shell was invisible.

This patches the one chokepoint every attacker command flows through -
`user_cmd = input(prompt)` in the main loop - to also append a JSON line to
/var/log/shellm.json, the file the agent already tails. Session context (srcip,
tier, persona) comes from the environment run.sh exports.

The static honeypot gets this from snoopy (LD_PRELOAD, real execve). shelLM has
no real filesystem and never executes anything, so the equivalent signal has to
be taken at the prompt.

Idempotent + pinned: runs against a fixed upstream commit (see Dockerfile).
"""
import sys

PATH = "/opt/shelLM/shelLMv2/LinuxSSHbot.py"

HELPER = '''

def _log_attacker_command(cmd):
    """Append one JSON line per attacker command to the SIEM feed.

    Best effort and never fatal: a honeypot that crashes on a logging error is a
    honeypot that tells the attacker it is a honeypot.
    """
    try:
        if not cmd:
            return
        import os as _os, json as _json, datetime as _dt
        path = _os.environ.get("SHELLM_CMD_LOG", "/var/log/shellm.json")
        event = {
            "honeypot": "shelLM",
            "event": "command",
            "protocol": "SSH",
            "srcip": _os.environ.get("SHELLM_SRCIP", "unknown"),
            "user": _os.environ.get("USER", "root"),
            "tier": _os.environ.get("SHELLM_TIER", "NONE"),
            "persona": _os.environ.get("SHELLM_PERSONA", ""),
            # Bound the field: a paste bomb must not blow up the alert pipeline.
            "command": cmd[:500],
            "time": _dt.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        }
        with open(path, "a", encoding="utf-8") as f:
            f.write(_json.dumps(event) + "\\n")
    except Exception:
        pass

'''

TARGET = "            user_cmd = input(prompt).strip()"
REPLACEMENT = ("            user_cmd = input(prompt).strip()\n"
               "            _log_attacker_command(user_cmd)")


def main():
    with open(PATH, "r", encoding="utf-8") as f:
        src = f.read()

    if "_log_attacker_command" in src:
        print("[patch] already applied; skipping.")
        return

    if TARGET not in src:
        print(f"[patch] ERROR: anchor not found in {PATH} (upstream changed?).",
              file=sys.stderr)
        sys.exit(1)

    # Helper goes just above main(), which is where the loop lives.
    src = src.replace("\ndef main():", HELPER + "\ndef main():", 1)
    src = src.replace(TARGET, REPLACEMENT, 1)

    with open(PATH, "w", encoding="utf-8") as f:
        f.write(src)
    print("[patch] shelLM now logs each attacker command to the SIEM feed")


if __name__ == "__main__":
    main()
