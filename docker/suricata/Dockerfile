FROM jasonish/suricata:latest
COPY local.rules /etc/suricata/rules/local.rules
CMD ["suricata", "-c", "/etc/suricata/suricata.yaml", "-s", "/etc/suricata/rules/local.rules", "-i", "eth0", "-v"]