# Beorn

Lightweight security and update agent for Linux machines. Scans for pending updates (apt, snap, flatpak), audits security posture (firewall, SSH, open ports, file permissions), applies security patches on schedule, and reports everything back to Mithrandir.

## Quick Install

```bash
pip install git+https://github.com/bhackerb/heimdall.git
beorn init
beorn scan
```

Or one-line:

```bash
curl -sSL https://raw.githubusercontent.com/bhackerb/heimdall/main/scripts/install.sh | bash
```

## Upgrading from Heimdall

If you are already running the legacy Heimdall agent, you can upgrade to Beorn using the automated migration script. This will migrate your configuration, identity, and systemd services.

```bash
git clone https://github.com/bhackerb/heimdall.git beorn_temp && \
cd beorn_temp && \
chmod +x scripts/migrate.sh && \
./scripts/migrate.sh && \
cd .. && rm -rf beorn_temp
```

## Configuration

Config lives at `~/.config/beorn/config.yaml`. Created by `beorn init` or copy from `config.example.yaml`.

Key settings:

| Setting | Default | Description |
|---------|---------|-------------|
| `hostname` | system hostname | Friendly name for this machine |
| `role` | workstation | workstation, server, or nas |
| `policy.auto_security` | true | Auto-apply security updates |
| `policy.maintenance_hour` | 3 | Hour (local) to apply updates |
| `policy.hold_packages` | nvidia, kernel, pg, docker | Never auto-update these |
| `schedule.update_scan_hours` | 6 | Update scan interval |
| `schedule.security_scan_hours` | 12 | Security audit interval |

Environment overrides: `HEIMDALL_API_KEY`, `HEIMDALL_ENGRAM_SECRET`.

## Commands

| Command | Description |
|---------|-------------|
| `beorn scan` | One-shot update + security scan, print results |
| `beorn status` | Quick summary of pending updates and security posture |
| `beorn apply` | Apply security updates (prompts for confirmation) |
| `beorn apply -y` | Apply without confirmation |
| `beorn report` | Scan and send full report to Mithrandir + Engram |
| `beorn daemon` | Run continuously on schedule |
| `beorn init` | Create config file interactively |

## Daemon (systemd)

```bash
sudo cp beorn.service /etc/systemd/system/beorn@.service
sudo systemctl enable beorn@$USER
sudo systemctl start beorn@$USER
```

## Mithrandir Integration

Beorn reports to two endpoints:

1. **Gwaihir API** (`POST /api/beorn/report`) — structured JSON with updates, security findings, and machine metadata. Requires `mithrandir.api_key` in config.

2. **Engram** (`brain_ingest` via HTTP MCP) — human-readable summary logged as episodic memory with tags `[beorn, security, <hostname>]`. Requires `mithrandir.engram_secret` in config.

Reports are always saved locally to `~/.config/beorn/state/reports/` as fallback.

## Architecture

```
                          +-------------------+
                          |    Mithrandir      |
                          |  (Gwaihir API)     |
                          +--------+----------+
                                   ^
                                   | HTTP POST
             +---------------------+---------------------+
             |                     |                      |
     +-------+-------+   +--------+--------+   +---------+-------+
     |   bhbserv      |   |    laptop       |   |    NAS          |
     |   beorn     |   |    beorn     |   |    beorn     |
     |   role: server |   |   role: wkst    |   |   role: nas     |
     +----------------+   +-----------------+   +-----------------+

Each Beorn instance:
  cli.py -----> scanner.py -----> apt/snap/flatpak
       |------> security.py ----> ufw/fail2ban/ssh/ports
       |------> policy.py ------> hold/auto-apply rules
       |------> updater.py -----> sudo apt install (security only)
       |------> reporter.py ----> Mithrandir + Engram + local file
       |------> config.py ------> ~/.config/beorn/config.yaml
```

## Security Checks

- **UFW**: active/inactive, rule count
- **fail2ban**: running, jail count, banned IPs
- **SSH**: root login, password auth, port
- **Open ports**: listening TCP, alerts on new ports since last scan
- **File permissions**: ~/.ssh, /etc/shadow
- **Unattended upgrades**: configured or not

## Update Policy

- Security updates auto-applied during maintenance window (default 3 AM)
- Held packages (nvidia, kernel, postgresql, docker) never auto-updated
- Non-security updates reported but not auto-applied
- Disk space checked before applying

## License

MIT
