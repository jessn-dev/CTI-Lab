# B2 — shelLM LLM SSH honeypot (depth / session consistency).
#
# shelLM (Stratosphere IPS) is NOT an SSH server -- it's a stdin/stdout LLM
# shell *chatbot* (readline loop). We expose it over SSH the way its paper does:
# a real OpenSSH server whose `ForceCommand` drops every login straight into the
# shelLM chatbot (see run.sh). Backed by the native Ollama on the host.
#
# Real Ubuntu userland + a baked-in Wazuh agent (same pattern as the static
# honeypot) so sessions land in the same SIEM.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        openssh-server \
        rsyslog \
        python3 \
        python3-venv \
        python3-pip \
        git \
        curl \
        ca-certificates \
        gnupg \
        lsb-release \
        procps \
    && rm -rf /var/lib/apt/lists/*

# Wazuh agent (matches the 4.8.0 manager).
RUN curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.8.0-1 \
    && rm -rf /var/lib/apt/lists/*

# --- shelLM (pinned) + a venv with its deps --------------------------------
# tiktoken is optional in the code (guarded by try/except) but installing it
# keeps the token-reset logic honest so a long session doesn't overflow Ollama.
RUN git clone https://github.com/stratosphereips/shelLM.git /opt/shelLM \
    && git -C /opt/shelLM checkout a480a5c6e623390786e662c34b6d1ecd8bb98af4
RUN python3 -m venv /opt/shelLM/venv \
    && /opt/shelLM/venv/bin/pip install --no-cache-dir \
        openai python-dotenv pyyaml requests tiktoken

# --- Honeypot bait: weak root:toor login, forced into the shelLM shell -------
RUN mkdir -p /var/run/sshd \
    && echo 'root:toor' | chpasswd \
    && sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?UsePAM.*/UsePAM yes/' /etc/ssh/sshd_config \
    # Every login runs the shelLM chatbot instead of a real shell.
    && printf '\nForceCommand /opt/shelLM/run.sh\nPermitTTY yes\n' >> /etc/ssh/sshd_config \
    # A honeypot accepts floods, not throttles them (see static honeypot notes).
    && printf 'MaxStartups 200:30:500\nMaxSessions 200\nLoginGraceTime 120\n' \
        >> /etc/ssh/sshd_config \
    && ssh-keygen -A

# Session-start logger + the ForceCommand launcher.
COPY --chmod=0755 services/shelLM/run.sh /opt/shelLM/run.sh

# Tell the agent to read auth.log (sshd) + shelLM's session log.
COPY services/shelLM/agent-shellm.conf /tmp/agent-shellm.conf
RUN cat /tmp/agent-shellm.conf >> /var/ossec/etc/ossec.conf && rm /tmp/agent-shellm.conf

COPY --chmod=0755 services/shelLM/entrypoint.sh /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
