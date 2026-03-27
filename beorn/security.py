"""Security posture checks — firewall, SSH, ports, permissions."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from beorn.config import BeornConfig, SecurityConfig, STATE_DIR


class Severity(str, Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"
    OK = "ok"


@dataclass
class Finding:
    check: str
    severity: Severity
    message: str
    detail: str = ""


@dataclass
class SecurityReport:
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    def summary(self) -> str:
        counts = {s: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity] += 1
        parts = []
        if counts[Severity.CRITICAL]:
            parts.append(f"{counts[Severity.CRITICAL]} CRITICAL")
        if counts[Severity.WARNING]:
            parts.append(f"{counts[Severity.WARNING]} warnings")
        if counts[Severity.INFO]:
            parts.append(f"{counts[Severity.INFO]} info")
        if counts[Severity.OK]:
            parts.append(f"{counts[Severity.OK]} ok")
        return " | ".join(parts) if parts else "no checks run"

    def format_text(self) -> str:
        """Format findings as readable text."""
        lines: list[str] = []
        for sev in [Severity.CRITICAL, Severity.WARNING, Severity.INFO, Severity.OK]:
            group = [f for f in self.findings if f.severity == sev]
            if not group:
                continue
            lines.append(f"\n[{sev.value.upper()}]")
            for f in group:
                lines.append(f"  {f.check}: {f.message}")
                if f.detail:
                    for dl in f.detail.splitlines():
                        lines.append(f"    {dl}")
        return "\n".join(lines)


def _run(cmd: list[str], timeout: int = 15) -> tuple[str, str, int]:
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"{cmd[0]}: not found", 127
    except subprocess.TimeoutExpired:
        return "", f"{cmd[0]}: timed out", 124


def check_ufw() -> list[Finding]:
    """Check UFW firewall status."""
    findings: list[Finding] = []

    if not shutil.which("ufw"):
        findings.append(Finding("ufw", Severity.WARNING, "UFW not installed"))
        return findings

    stdout, stderr, rc = _run(["sudo", "ufw", "status", "verbose"])
    if rc != 0:
        findings.append(Finding("ufw", Severity.WARNING, f"Could not check UFW: {stderr.strip()}"))
        return findings

    if "Status: inactive" in stdout:
        findings.append(Finding("ufw", Severity.CRITICAL, "UFW firewall is INACTIVE"))
    elif "Status: active" in stdout:
        # Count rules
        rules = [l for l in stdout.splitlines() if re.match(r"^\d+|^[\w/]+\s+(ALLOW|DENY|REJECT)", l)]
        findings.append(Finding(
            "ufw", Severity.OK,
            f"UFW active with {len(rules)} rules",
            detail=stdout.strip(),
        ))
    else:
        findings.append(Finding("ufw", Severity.WARNING, "Could not parse UFW status"))

    return findings


def check_fail2ban() -> list[Finding]:
    """Check fail2ban status."""
    findings: list[Finding] = []

    if not shutil.which("fail2ban-client"):
        findings.append(Finding("fail2ban", Severity.WARNING, "fail2ban not installed"))
        return findings

    stdout, stderr, rc = _run(["sudo", "fail2ban-client", "status"])
    if rc != 0:
        findings.append(Finding(
            "fail2ban", Severity.WARNING,
            f"fail2ban not running: {stderr.strip()}",
        ))
        return findings

    # Parse jails
    jail_match = re.search(r"Jail list:\s+(.+)", stdout)
    if jail_match:
        jails = [j.strip() for j in jail_match.group(1).split(",") if j.strip()]
        detail_lines: list[str] = []

        for jail in jails:
            jstdout, _, jrc = _run(["sudo", "fail2ban-client", "status", jail])
            if jrc == 0:
                banned_match = re.search(r"Currently banned:\s+(\d+)", jstdout)
                banned = int(banned_match.group(1)) if banned_match else 0
                detail_lines.append(f"{jail}: {banned} banned")

        findings.append(Finding(
            "fail2ban", Severity.OK,
            f"{len(jails)} jails active",
            detail="\n".join(detail_lines),
        ))
    else:
        findings.append(Finding("fail2ban", Severity.WARNING, "No jails configured"))

    return findings


def check_ssh_config() -> list[Finding]:
    """Check SSH server configuration for security issues."""
    findings: list[Finding] = []
    sshd_config = Path("/etc/ssh/sshd_config")

    if not sshd_config.exists():
        findings.append(Finding("ssh", Severity.INFO, "No sshd_config found (SSH server not installed?)"))
        return findings

    try:
        content = sshd_config.read_text()
    except PermissionError:
        # Try with sudo
        stdout, stderr, rc = _run(["sudo", "cat", "/etc/ssh/sshd_config"])
        if rc != 0:
            findings.append(Finding("ssh", Severity.WARNING, "Cannot read sshd_config"))
            return findings
        content = stdout

    # Also read config snippets from sshd_config.d/
    config_d = Path("/etc/ssh/sshd_config.d")
    if config_d.is_dir():
        for conf_file in sorted(config_d.glob("*.conf")):
            try:
                content += "\n" + conf_file.read_text()
            except PermissionError:
                pass

    # Check PermitRootLogin
    root_match = re.search(r"^\s*PermitRootLogin\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
    if root_match:
        val = root_match.group(1).lower()
        if val == "yes":
            findings.append(Finding("ssh", Severity.CRITICAL, "Root login is ENABLED"))
        elif val in ("no", "prohibit-password"):
            findings.append(Finding("ssh", Severity.OK, f"Root login: {val}"))
    else:
        findings.append(Finding("ssh", Severity.WARNING, "PermitRootLogin not explicitly set"))

    # Check PasswordAuthentication
    pass_match = re.search(r"^\s*PasswordAuthentication\s+(\S+)", content, re.MULTILINE | re.IGNORECASE)
    if pass_match:
        val = pass_match.group(1).lower()
        if val == "yes":
            findings.append(Finding("ssh", Severity.WARNING, "Password authentication is ENABLED"))
        else:
            findings.append(Finding("ssh", Severity.OK, "Password authentication disabled"))
    else:
        findings.append(Finding("ssh", Severity.WARNING, "PasswordAuthentication not explicitly set"))

    # Check port
    port_match = re.search(r"^\s*Port\s+(\d+)", content, re.MULTILINE)
    port = int(port_match.group(1)) if port_match else 22
    if port == 22:
        findings.append(Finding("ssh", Severity.INFO, "SSH on default port 22"))
    else:
        findings.append(Finding("ssh", Severity.OK, f"SSH on non-default port {port}"))

    return findings


def check_open_ports() -> list[Finding]:
    """Check listening TCP ports."""
    findings: list[Finding] = []

    if not shutil.which("ss"):
        findings.append(Finding("ports", Severity.WARNING, "ss command not available"))
        return findings

    stdout, stderr, rc = _run(["ss", "-tlnp"])
    if rc != 0:
        findings.append(Finding("ports", Severity.WARNING, f"ss failed: {stderr.strip()}"))
        return findings

    ports: list[str] = []
    for line in stdout.strip().splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 4:
            local_addr = parts[3]
            # Extract port
            port_match = re.search(r":(\d+)$", local_addr)
            if port_match:
                port = port_match.group(1)
                process = parts[-1] if len(parts) > 5 else ""
                ports.append(f":{port} {process}")

    if ports:
        findings.append(Finding(
            "ports", Severity.INFO,
            f"{len(ports)} listening TCP ports",
            detail="\n".join(ports),
        ))
    else:
        findings.append(Finding("ports", Severity.OK, "No listening TCP ports"))

    # Check for new ports vs previous scan
    _check_new_ports(ports, findings)

    return findings


def _check_new_ports(current_ports: list[str], findings: list[Finding]) -> None:
    """Compare current ports to previous scan, flag new ones."""
    state_file = STATE_DIR / "known_ports.txt"

    current_set = set(current_ports)

    if state_file.exists():
        previous = set(state_file.read_text().strip().splitlines())
        new_ports = current_set - previous
        if new_ports:
            findings.append(Finding(
                "ports", Severity.WARNING,
                f"{len(new_ports)} NEW ports since last scan",
                detail="\n".join(sorted(new_ports)),
            ))

    # Save current state
    try:
        state_file.parent.mkdir(parents=True, exist_ok=True)
        state_file.write_text("\n".join(sorted(current_set)) + "\n")
    except OSError:
        pass


def check_file_permissions() -> list[Finding]:
    """Check permissions on sensitive files and directories."""
    findings: list[Finding] = []

    checks = [
        (Path.home() / ".ssh", 0o700, "directory"),
        (Path.home() / ".ssh" / "authorized_keys", 0o600, "file"),
        (Path("/etc/shadow"), 0o640, "file"),
    ]

    for path, expected_mode, kind in checks:
        if not path.exists():
            continue
        try:
            actual = path.stat().st_mode & 0o777
            if actual > expected_mode:
                findings.append(Finding(
                    "permissions", Severity.WARNING,
                    f"{path} is {oct(actual)} (should be {oct(expected_mode)} or stricter)",
                ))
            else:
                findings.append(Finding(
                    "permissions", Severity.OK,
                    f"{path} permissions OK ({oct(actual)})",
                ))
        except PermissionError:
            pass  # Can't check, skip

    return findings


def check_unattended_upgrades() -> list[Finding]:
    """Check if unattended-upgrades is configured."""
    findings: list[Finding] = []

    auto_conf = Path("/etc/apt/apt.conf.d/20auto-upgrades")
    if not auto_conf.exists():
        findings.append(Finding(
            "unattended-upgrades", Severity.INFO,
            "Automatic security updates not configured",
        ))
        return findings

    try:
        content = auto_conf.read_text()
        if 'Unattended-Upgrade "1"' in content or "Unattended-Upgrade \"1\"" in content:
            findings.append(Finding(
                "unattended-upgrades", Severity.OK,
                "Automatic security updates enabled",
            ))
        else:
            findings.append(Finding(
                "unattended-upgrades", Severity.INFO,
                "unattended-upgrades installed but may not be enabled",
            ))
    except PermissionError:
        findings.append(Finding(
            "unattended-upgrades", Severity.INFO,
            "Cannot read auto-upgrades config",
        ))

    return findings


def full_security_scan(config: BeornConfig) -> SecurityReport:
    """Run all configured security checks."""
    report = SecurityReport()
    sec = config.security

    checks: list[tuple[bool, callable]] = [
        (sec.check_ufw, check_ufw),
        (sec.check_fail2ban, check_fail2ban),
        (sec.check_ssh_config, check_ssh_config),
        (sec.check_open_ports, check_open_ports),
        (True, check_file_permissions),
        (True, check_unattended_upgrades),
    ]

    for enabled, checker in checks:
        if not enabled:
            continue
        try:
            report.findings.extend(checker())
        except Exception as e:
            report.errors.append(f"{checker.__name__}: {e}")

    return report
