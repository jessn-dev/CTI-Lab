# Sidecar Wazuh agent for beelzebub.
# beelzebub ships as a scratch image (no shell, no room for an agent), so this
# small companion tails beelzebub's JSON event log from the shared volume and
# forwards it to the Wazuh manager as a distinct agent ("beelzebub-agent").
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg lsb-release \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.8.0-1 \
    && rm -rf /var/lib/apt/lists/*

# Tell the agent to read beelzebub's JSON log (mounted at /logs).
COPY beelzebub-localfile.conf /tmp/bz.conf
RUN cat /tmp/bz.conf >> /var/ossec/etc/ossec.conf && rm /tmp/bz.conf

COPY --chmod=0755 entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
