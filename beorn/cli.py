"""CLI commands — scan, status, report, apply, daemon, init."""

from __future__ import annotations

import argparse
import shutil
import sys
import time
from datetime import datetime
from pathlib import Path

from beorn import __version__
from beorn.config import (
    CONFIG_PATH,
    BeornConfig,
    ensure_dirs,
    load_config,
)


def cmd_scan(args: argparse.Namespace, config: BeornConfig) -> int:
    """One-shot update + security scan, print results."""
    from beorn.scanner import full_scan
    from beorn.security import full_security_scan
    from beorn.engine import Carrock

    print(f"Beorn scanning {config.hostname} ({config.role})...\n")

    # Hive (Plugins)
    print("=== The Hive (Plugins) ===")
    carrock = Carrock(config)
    bee_results = carrock.run_all()
    for name, res in bee_results.items():
        print(f"  {name.upper()}: {res.summary}")
        if res.data.get("changes"):
            for change in res.data["changes"]:
                print(f"    ! {change}")
    print()

    # Update scan
    print("=== Updates ===")
    scan = full_scan()
    print(scan.summary())
    if scan.updates:
        for u in scan.updates:
            marker = " [SECURITY]" if u.update_type.value == "security" else ""
            print(
                f"  {u.source}: {u.package} {u.current_version} -> {u.new_version}{marker}"
            )
    if scan.reboot_required:
        print("\n  *** REBOOT REQUIRED ***")
    if scan.restart_services:
        print(f"\n  Services needing restart: {', '.join(scan.restart_services)}")
    if scan.errors:
        print(f"\n  Errors: {'; '.join(scan.errors)}")

    # Security scan
    print("\n=== Security ===")
    sec_report = full_security_scan(config)
    print(sec_report.summary())
    print(sec_report.format_text())
    if sec_report.errors:
        print(f"\n  Errors: {'; '.join(sec_report.errors)}")

    return 0


def cmd_status(args: argparse.Namespace, config: BeornConfig) -> int:
    """Show current state — pending updates, security posture."""
    from beorn.scanner import full_scan, check_reboot_required
    from beorn.security import full_security_scan

    print(f"Beorn v{__version__} — {config.hostname} ({config.role})")
    print(f"Config: {CONFIG_PATH}")
    print()

    scan = full_scan()
    sec = full_security_scan(config)

    print(f"Updates:  {scan.summary()}")
    print(f"Security: {sec.summary()}")

    if check_reboot_required():
        print("\n*** REBOOT REQUIRED ***")

    return 0


def cmd_apply(args: argparse.Namespace, config: BeornConfig) -> int:
    """Apply security updates."""
    from beorn.scanner import full_scan
    from beorn.policy import get_auto_applicable, classify_scan
    from beorn.updater import apply_updates

    scan = full_scan()
    classified = classify_scan(scan, config)
    applicable = classified["auto_apply"]

    if not applicable:
        print("No security updates to apply.")
        return 0

    print(f"Security updates to apply ({len(applicable)}):")
    for u in applicable:
        print(f"  {u.package} {u.current_version} -> {u.new_version}")

    if classified["held"]:
        print(f"\nHeld packages ({len(classified['held'])}):")
        for u in classified["held"]:
            print(f"  {u.package} (held by policy)")

    if not args.yes:
        try:
            answer = input("\nProceed? [y/N] ").strip().lower()
            if answer not in ("y", "yes"):
                print("Aborted.")
                return 1
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.")
            return 1

    result = apply_updates(applicable, config)
    print(f"\nResult: {result.summary()}")
    for line in result.log:
        print(f"  {line}")

    return 0 if result.success else 1


def cmd_report(args: argparse.Namespace, config: BeornConfig) -> int:
    """Send full report to Mithrandir."""
    from beorn.scanner import full_scan
    from beorn.security import full_security_scan
    from beorn.reporter import send_report

    print(f"Scanning {config.hostname}...")
    scan = full_scan()
    sec = full_security_scan(config)

    print("Sending report...")
    messages = send_report(config, scan, sec)
    for msg in messages:
        print(f"  {msg}")

    return 0


def cmd_daemon(args: argparse.Namespace, config: BeornConfig) -> int:
    """Run as background daemon — scan on schedule, auto-apply security."""
    from beorn.scanner import full_scan
    from beorn.security import full_security_scan
    from beorn.policy import get_auto_applicable, should_auto_apply_now
    from beorn.updater import apply_updates
    from beorn.reporter import send_report
    from beorn.engine import Carrock

    print(f"Beorn daemon starting — {config.hostname} ({config.role})")
    print(f"  Update scan every {config.schedule.update_scan_hours}h")
    print(f"  Security scan every {config.schedule.security_scan_hours}h")
    print(f"  Report every {config.schedule.report_hours}h")
    print(f"  Pulse check every 5m")
    print(f"  Maintenance window: {config.policy.maintenance_hour}:00")
    print()

    carrock = Carrock(config)
    last_update_scan = 0.0
    last_security_scan = 0.0
    last_report = 0.0

    update_interval = config.schedule.update_scan_hours * 3600
    security_interval = config.schedule.security_scan_hours * 3600
    report_interval = config.schedule.report_hours * 3600

    try:
        while True:
            now = time.time()
            scan_result = None
            sec_result = None

            # Pulse Check (The Hive)
            print(f"[{_ts()}] Heartbeat Pulse...")
            pulse_results = carrock.run_pulse()
            for name, res in pulse_results.items():
                if res.data.get("changes"):
                    print(f"[{_ts()}]   ALERT [{name.upper()}]: {res.summary}")
                    # In the future, this would trigger an immediate high-priority report

            # Update scan
            if now - last_update_scan >= update_interval:
                print(f"[{_ts()}] Running update scan...")
                scan_result = full_scan()
                print(f"[{_ts()}] Updates: {scan_result.summary()}")
                last_update_scan = now

                # Auto-apply security updates if in maintenance window
                if should_auto_apply_now(config):
                    applicable = get_auto_applicable(scan_result, config)
                    if applicable:
                        print(
                            f"[{_ts()}] Auto-applying {len(applicable)} security updates..."
                        )
                        result = apply_updates(applicable, config)
                        print(f"[{_ts()}] Apply result: {result.summary()}")

            # Security scan
            if now - last_security_scan >= security_interval:
                print(f"[{_ts()}] Running security scan...")
                sec_result = full_security_scan(config)
                print(f"[{_ts()}] Security: {sec_result.summary()}")
                last_security_scan = now

            # Report
            if now - last_report >= report_interval:
                if not scan_result:
                    scan_result = full_scan()
                if not sec_result:
                    sec_result = full_security_scan(config)
                print(f"[{_ts()}] Sending report to Mithrandir...")
                messages = send_report(config, scan_result, sec_result)
                for msg in messages:
                    print(f"[{_ts()}]   {msg}")
                last_report = now

            # Sleep 5 minutes between checks
            time.sleep(300)

    except KeyboardInterrupt:
        print(f"\n[{_ts()}] Daemon stopped.")
        return 0


def cmd_init(args: argparse.Namespace, config: BeornConfig) -> int:
    """Create config file interactively."""
    ensure_dirs()

    if CONFIG_PATH.exists() and not args.force:
        print(f"Config already exists at {CONFIG_PATH}")
        print("Use --force to overwrite.")
        return 1

    import socket

    hostname = input(f"Hostname [{socket.gethostname()}]: ").strip()
    if not hostname:
        hostname = socket.gethostname()

    role = input("Role (workstation/server/nas) [workstation]: ").strip()
    if role not in ("workstation", "server", "nas"):
        role = "workstation"

    api_key = input("Mithrandir API key (blank to skip): ").strip()
    engram_secret = input("Engram secret (blank to skip): ").strip()

    # Find the example config
    example = Path(__file__).parent.parent / "config.example.yaml"
    if example.exists():
        content = example.read_text()
    else:
        # Inline fallback
        content = _DEFAULT_CONFIG

    content = content.replace('hostname: "laptop"', f'hostname: "{hostname}"')
    content = content.replace('role: "workstation"', f'role: "{role}"')
    if api_key:
        content = content.replace('api_key: ""', f'api_key: "{api_key}"')
    if engram_secret:
        content = content.replace(
            'engram_secret: ""', f'engram_secret: "{engram_secret}"'
        )

    CONFIG_PATH.write_text(content)
    print(f"\nConfig written to {CONFIG_PATH}")
    print("Edit it to fine-tune settings, then run: beorn scan")

    return 0


def _ts() -> str:
    """Current timestamp string."""
    return datetime.now().strftime("%H:%M:%S")


_DEFAULT_CONFIG = """\
hostname: "unknown"
role: "workstation"
mithrandir:
  url: "https://gwaihir.bhackerb.com"
  api_key: ""
  engram_url: "https://engram.bhackerb.com/mcp"
  engram_secret: ""
schedule:
  update_scan_hours: 6
  security_scan_hours: 12
  report_hours: 24
policy:
  auto_security: true
  hold_packages:
    - "nvidia-*"
    - "linux-image-*"
    - "postgresql-*"
    - "docker-ce"
  maintenance_hour: 3
security:
  check_ufw: true
  check_fail2ban: true
  check_ssh_config: true
  check_open_ports: true
  check_listening_services: true
  alert_on_new_port: true
"""


def main() -> None:
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        prog="beorn",
        description="Beorn — lightweight security & update agent",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"beorn {__version__}",
    )
    parser.add_argument(
        "--config",
        type=Path,
        default=None,
        help="Path to config file (default: ~/.config/beorn/config.yaml)",
    )

    sub = parser.add_subparsers(dest="command")

    # scan
    sub.add_parser("scan", help="One-shot update + security scan")

    # status
    sub.add_parser("status", help="Show current state")

    # apply
    apply_p = sub.add_parser("apply", help="Apply security updates")
    apply_p.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    # report
    sub.add_parser("report", help="Send full report to Mithrandir")

    # daemon
    sub.add_parser("daemon", help="Run as background daemon")

    # init
    init_p = sub.add_parser("init", help="Create config file")
    init_p.add_argument(
        "--force", action="store_true", help="Overwrite existing config"
    )

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(0)

    config = load_config(args.config)

    commands = {
        "scan": cmd_scan,
        "status": cmd_status,
        "apply": cmd_apply,
        "report": cmd_report,
        "daemon": cmd_daemon,
        "init": cmd_init,
    }

    handler = commands.get(args.command)
    if handler:
        sys.exit(handler(args, config))
    else:
        parser.print_help()
        sys.exit(1)
