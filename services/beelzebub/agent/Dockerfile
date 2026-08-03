# Sidecar Wazuh agent for beelzebub.
# beelzebub ships as a scratch image (no shell, no room for an agent), so this
# small companion tails beelzebub's JSON event log from the shared volume and
# forwards it to the Wazuh manager as a distinct agent ("beelzebub-agent").
FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl ca-certificates gnupg lsb-release \
        iptables \
    && curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | \
        gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import \
    && chmod 644 /usr/share/keyrings/wazuh.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
        > /etc/apt/sources.list.d/wazuh.list \
    && apt-get update \
    && WAZUH_MANAGER="wazuh.manager" apt-get install -y wazuh-agent=4.8.0-1 \
    && rm -rf /var/lib/apt/lists/*

# Tell the agent to read beelzebub's JSON log (mounted at /logs).
COPY services/beelzebub/agent/beelzebub-localfile.conf /tmp/bz.conf
RUN cat /tmp/bz.conf >> /var/ossec/etc/ossec.conf && rm /tmp/bz.conf

# beelzebub ships as a scratch image: no shell, so it cannot host an Active
# Response script or run iptables itself. This sidecar shares beelzebub's network
# namespace (see compose/beelzebub.yml), so a ban applied here covers beelzebub's
# traffic - which is what makes the lab-wide tripwire ban true for all three
# honeypots instead of two.
COPY --chmod=0750 src/soar/active_defense.py /var/ossec/active-response/bin/active_defense.py
RUN chown root:wazuh /var/ossec/active-response/bin/active_defense.py

COPY --chmod=0755 services/beelzebub/agent/entrypoint.sh /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
