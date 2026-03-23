# Heimdall

Lightweight security and update agent for Linux machines. Scans for pending updates (apt, snap, flatpak), audits security posture (firewall, SSH, open ports, file permissions), applies security patches on schedule, and reports everything back to Mithrandir.

## Quick Install

```bash
pip install git+https://github.com/bhackerb/heimdall.git
heimdall init
heimdall scan
```

Or one-line:

```bash
curl -sSL https://raw.githubusercontent.com/bhackerb/heimdall/main/scripts/install.sh | bash
```

## Configuration

Config lives at `~/.config/heimdall/config.yaml`. Created by `heimdall init` or copy from `config.example.yaml`.

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
| `heimdall scan` | One-shot update + security scan, print results |
| `heimdall status` | Quick summary of pending updates and security posture |
| `heimdall apply` | Apply security updates (prompts for confirmation) |
| `heimdall apply -y` | Apply without confirmation |
| `heimdall report` | Scan and send full report to Mithrandir + Engram |
| `heimdall daemon` | Run continuously on schedule |
| `heimdall init` | Create config file interactively |

## Daemon (systemd)

```bash
sudo cp heimdall.service /etc/systemd/system/heimdall@.service
sudo systemctl enable heimdall@$USER
sudo systemctl start heimdall@$USER
```

## Mithrandir Integration

Heimdall reports to two endpoints:

1. **Gwaihir API** (`POST /api/heimdall/report`) — structured JSON with updates, security findings, and machine metadata. Requires `mithrandir.api_key` in config.

2. **Engram** (`brain_ingest` via HTTP MCP) — human-readable summary logged as episodic memory with tags `[heimdall, security, <hostname>]`. Requires `mithrandir.engram_secret` in config.

Reports are always saved locally to `~/.config/heimdall/state/reports/` as fallback.

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
     |   heimdall     |   |    heimdall     |   |    heimdall     |
     |   role: server |   |   role: wkst    |   |   role: nas     |
     +----------------+   +-----------------+   +-----------------+

Each Heimdall instance:
  cli.py -----> scanner.py -----> apt/snap/flatpak
       |------> security.py ----> ufw/fail2ban/ssh/ports
       |------> policy.py ------> hold/auto-apply rules
       |------> updater.py -----> sudo apt install (security only)
       |------> reporter.py ----> Mithrandir + Engram + local file
       |------> config.py ------> ~/.config/heimdall/config.yaml
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
