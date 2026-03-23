"""Update scanning — apt, snap, flatpak, pip."""

from __future__ import annotations

import re
import shutil
import subprocess
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional


class UpdateType(str, Enum):
    SECURITY = "security"
    BUGFIX = "bugfix"
    FEATURE = "feature"
    UNKNOWN = "unknown"


@dataclass
class PendingUpdate:
    package: str
    current_version: str
    new_version: str
    source: str  # apt, snap, flatpak
    update_type: UpdateType = UpdateType.UNKNOWN
    repository: str = ""


@dataclass
class ScanResult:
    updates: list[PendingUpdate] = field(default_factory=list)
    reboot_required: bool = False
    restart_services: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def security_count(self) -> int:
        return sum(1 for u in self.updates if u.update_type == UpdateType.SECURITY)

    @property
    def total_count(self) -> int:
        return len(self.updates)

    def summary(self) -> str:
        """One-line summary of scan results."""
        parts = [f"{self.total_count} updates"]
        if self.security_count:
            parts.append(f"{self.security_count} security")
        if self.reboot_required:
            parts.append("REBOOT REQUIRED")
        if self.restart_services:
            parts.append(f"{len(self.restart_services)} services need restart")
        return " | ".join(parts)


# Patterns that indicate a security update
_SECURITY_PATTERNS = [
    r"-security",
    r"CVE-\d{4}",
    r"USN-\d+",
    r"DSA-\d+",
]

# Patterns that indicate potentially breaking updates
_BREAKING_PATTERNS = [
    r"linux-image",
    r"linux-headers",
    r"nvidia-",
    r"postgresql-\d+",
    r"docker-ce",
    r"systemd",
]


def _classify_update(package: str, repository: str) -> UpdateType:
    """Classify an update as security, bugfix, feature, or unknown."""
    combined = f"{package} {repository}"
    for pat in _SECURITY_PATTERNS:
        if re.search(pat, combined, re.IGNORECASE):
            return UpdateType.SECURITY
    return UpdateType.UNKNOWN


def _run(cmd: list[str], timeout: int = 30) -> tuple[str, str, int]:
    """Run a command and return (stdout, stderr, returncode)."""
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return "", f"{cmd[0]}: not found", 127
    except subprocess.TimeoutExpired:
        return "", f"{cmd[0]}: timed out after {timeout}s", 124


def scan_apt() -> tuple[list[PendingUpdate], list[str]]:
    """Scan for pending apt updates."""
    updates: list[PendingUpdate] = []
    errors: list[str] = []

    if not shutil.which("apt"):
        return updates, errors

    # Refresh package lists
    stdout, stderr, rc = _run(["sudo", "apt", "update", "-qq"], timeout=120)
    if rc != 0 and "Could not get lock" in stderr:
        errors.append("apt: package manager locked (another process running?)")
        return updates, errors

    # List upgradable
    stdout, stderr, rc = _run(["apt", "list", "--upgradable"], timeout=30)
    if rc != 0:
        errors.append(f"apt list failed: {stderr.strip()}")
        return updates, errors

    for line in stdout.strip().splitlines():
        if line.startswith("Listing") or not line.strip():
            continue
        # Format: package/repo version arch [upgradable from: old_version]
        match = re.match(
            r"^(\S+)/(\S+)\s+(\S+)\s+\S+\s+\[upgradable from:\s+(\S+)\]",
            line,
        )
        if match:
            pkg, repo, new_ver, old_ver = match.groups()
            update_type = _classify_update(pkg, repo)
            updates.append(PendingUpdate(
                package=pkg,
                current_version=old_ver,
                new_version=new_ver,
                source="apt",
                update_type=update_type,
                repository=repo,
            ))

    return updates, errors


def scan_snap() -> tuple[list[PendingUpdate], list[str]]:
    """Scan for pending snap updates."""
    updates: list[PendingUpdate] = []
    errors: list[str] = []

    if not shutil.which("snap"):
        return updates, errors

    stdout, stderr, rc = _run(["snap", "refresh", "--list"], timeout=30)
    if rc != 0:
        # Exit code 0 = updates available, non-zero can mean "no updates"
        if "no updates" in stderr.lower() or "no updates" in stdout.lower():
            return updates, errors
        if stderr.strip():
            errors.append(f"snap: {stderr.strip()}")
        return updates, errors

    for line in stdout.strip().splitlines()[1:]:  # Skip header
        parts = line.split()
        if len(parts) >= 2:
            updates.append(PendingUpdate(
                package=parts[0],
                current_version=parts[1] if len(parts) > 1 else "",
                new_version=parts[2] if len(parts) > 2 else "",
                source="snap",
            ))

    return updates, errors


def scan_flatpak() -> tuple[list[PendingUpdate], list[str]]:
    """Scan for pending flatpak updates."""
    updates: list[PendingUpdate] = []
    errors: list[str] = []

    if not shutil.which("flatpak"):
        return updates, errors

    stdout, stderr, rc = _run(
        ["flatpak", "remote-ls", "--updates", "--columns=name,version"],
        timeout=30,
    )
    if rc != 0:
        if stderr.strip():
            errors.append(f"flatpak: {stderr.strip()}")
        return updates, errors

    for line in stdout.strip().splitlines():
        parts = line.split("\t")
        if parts and parts[0].strip():
            updates.append(PendingUpdate(
                package=parts[0].strip(),
                current_version="",
                new_version=parts[1].strip() if len(parts) > 1 else "",
                source="flatpak",
            ))

    return updates, errors


def check_reboot_required() -> bool:
    """Check if the system needs a reboot."""
    return Path("/var/run/reboot-required").exists()


def check_restart_services() -> list[str]:
    """Check for services that need restarting (via needrestart or checkrestart)."""
    services: list[str] = []

    if shutil.which("needrestart"):
        stdout, stderr, rc = _run(
            ["sudo", "needrestart", "-b"], timeout=30,
        )
        if rc == 0:
            for line in stdout.splitlines():
                match = re.match(r"NEEDRESTART-SVC:\s+(.+)", line)
                if match:
                    services.append(match.group(1).strip())

    return services


def full_scan() -> ScanResult:
    """Run a complete update scan across all package managers."""
    result = ScanResult()

    for scanner in [scan_apt, scan_snap, scan_flatpak]:
        updates, errors = scanner()
        result.updates.extend(updates)
        result.errors.extend(errors)

    result.reboot_required = check_reboot_required()
    result.restart_services = check_restart_services()

    return result
