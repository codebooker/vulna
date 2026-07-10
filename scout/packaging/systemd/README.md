# VulnaScout systemd service

Runs the VulnaScout agent as a hardened systemd service.

## Install

```bash
# 1. Build (or download) the binary and install it.
sudo install -m 0755 vulnascout /usr/local/bin/vulnascout

# 2. Create a dedicated, unprivileged system user.
sudo useradd --system --home /var/lib/vulna --shell /usr/sbin/nologin vulna || true

# 3. Configuration (see agent.json.example).
sudo install -d -m 0750 -o vulna -g vulna /etc/vulna
sudo install -m 0640 -o vulna -g vulna agent.json.example /etc/vulna/agent.json
# Edit /etc/vulna/agent.json and set at least "server_url".

# 4. Enroll once, as the service user, with a token from VulnaDash.
sudo -u vulna vulnascout enroll --config /etc/vulna/agent.json --token "vscout_..."

# 5. Install and start the service.
sudo install -m 0644 vulnascout.service /etc/systemd/system/vulnascout.service
sudo systemctl daemon-reload
sudo systemctl enable --now vulnascout.service
sudo systemctl status vulnascout.service
```

## Notes

- The unit uses `StateDirectory=vulna` and `ConfigurationDirectory=vulna`, so
  systemd manages `/var/lib/vulna` and `/etc/vulna` with the correct owner.
- The agent stores its private key (`0600`), issued certificate, orchestrator
  CA, and `state.json` under `/var/lib/vulna`. The private key never leaves the
  host.
- Hardening follows build-plan Section 18.4. The agent runs with **no**
  capabilities; raw-socket capabilities for scanners are added later, scoped to
  a scanner helper rather than the whole agent.
- Communication is outbound-only over HTTPS with mutual TLS. No inbound port is
  opened or required.
