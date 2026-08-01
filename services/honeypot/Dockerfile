# Linux SSH honeypot with a baked-in Wazuh agent.
# Real Ubuntu userland (bash, useradd, rsyslog/auth.log) so the post-exploit
# phases of the simulation actually execute and generate telemetry that the
# Wazuh manager can detect.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

# Base tooling + a real sshd + rsyslog (writes /var/log/auth.log) + iptables
# (needed by the Active Response script) + curl (used by the malware-drop phase).
RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        rsyslog \
        iptables \
        curl \
        ca-certificates \
        gnupg \
        lsb-release \
        python3 \
        procps \
        sudo \
        snoopy \
    && rm -rf /var/lib/apt/lists/*

# Command auditing (Phase C1): snoopy is an LD_PRELOAD execve logger — it captures
# EVERY command run on the box, including the non-interactive `exec_command`s the
# attack sim uses (which bash history / auditd would miss; auditd also can't get
# the kernel audit netlink inside a container). We configure it here but only
# activate the preload at runtime (entrypoint), so build-step commands aren't
# logged. One line per command -> /var/log/snoopy.log -> Wazuh reads it.
# cli=%{env:SSH_CLIENT} captures the attacker's source IP (sshd sets SSH_CLIENT in
# the session env, even for non-interactive exec) so command events carry srcip -
# used by the tier correlation and by the tripwire-driven ban (Phase C5).
#
# filter_chain drops the SIEM's own housekeeping: wazuh-modulesd/logcollector run
# `df -P`, `last -n 20` and a netstat|sed|sort pipeline on a timer, and execd
# spawns our Active-Response scripts - together ~95% of the log, all at base
# level 2, none of it attacker activity. Everything an attacker runs is spawned
# by sshd, so excluding these process trees costs no detection. (uid filters are
# useless here: every process in the container is root.)
# NOTE the truncated "wazuh-logcollec": the filter matches the kernel's comm,
# which is capped at 15 characters - spell it out or logcollector's `df`/`last`/
# netstat pipelines keep leaking into the log.
RUN printf '\nmessage_format = "snoopy: user=%%{username} uid=%%{uid} tty=%%{tty} cwd=%%{cwd} cli=%%{env:SSH_CLIENT} cmd=%%{cmdline}"\nfilter_chain = "exclude_spawns_of:wazuh-modulesd,wazuh-logcollec,wazuh-logcollector,wazuh-agentd,wazuh-execd,wazuh-syscheckd,wazuh-control"\noutput = file:/var/log/snoopy.log\n' \
        >> /etc/snoopy.ini

# Install the Wazuh agent (matches the 4.8.0 manager).
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.8.0-1 \
    && rm -rf /var/lib/apt/lists/*

# --- Honeypot bait: weak, highly targeted root:toor login over SSH -----------
RUN mkdir -p /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    # A honeypot should accept floods, not throttle them. Default MaxStartups
    # (10:30:100) drops rapid brute-force connections, which under emulation
    # shows up as "Error reading SSH protocol banner" on the attacker side.
    && printf '\nMaxStartups 200:30:500\nMaxSessions 200\nLoginGraceTime 120\n' \
        >> /etc/ssh/sshd_config

# --- Custom Active Response executable (triggered by the manager) -------------
# Build context is the project root (see docker-compose.yml), so paths are
# relative to it.
COPY --chmod=0750 src/soar/active_defense.py /var/ossec/active-response/bin/active_defense.py
COPY --chmod=0750 src/soar/engage.py /var/ossec/active-response/bin/engage.py
COPY --chmod=0750 src/soar/persona.py /var/ossec/active-response/bin/persona.py
RUN chown root:wazuh /var/ossec/active-response/bin/active_defense.py \
                     /var/ossec/active-response/bin/engage.py \
                     /var/ossec/active-response/bin/persona.py

# --- Extra File Integrity Monitoring on attacker drop zones ------------------
COPY services/honeypot/agent-fim.conf /tmp/agent-fim.conf
RUN cat /tmp/agent-fim.conf >> /var/ossec/etc/ossec.conf && rm /tmp/agent-fim.conf

COPY --chmod=0755 services/honeypot/entrypoint.sh /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
