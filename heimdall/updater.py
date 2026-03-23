"""Apply updates with pre/post checks and safety guards."""

from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Optional

from heimdall.config import HeimdallConfig
from heimdall.scanner import PendingUpdate


@dataclass
class UpdateResult:
    success: bool = False
    applied: list[str] = field(default_factory=list)
    failed: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    log: list[str] = field(default_factory=list)

    def summary(self) -> str:
        parts = []
        if self.applied:
            parts.append(f"{len(self.applied)} applied")
        if self.failed:
            parts.append(f"{len(self.failed)} FAILED")
        if self.skipped:
            parts.append(f"{len(self.skipped)} skipped")
        return " | ".join(parts) if parts else "nothing to do"


def _run(cmd: list[str], timeout: int = 300) -> tuple[str, str, int]:
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


def check_disk_space(min_mb: int = 500) -> tuple[bool, str]:
    """Verify enough disk space on /. Returns (ok, message)."""
    try:
        stat = shutil.disk_usage("/")
        free_mb = stat.free // (1024 * 1024)
        if free_mb < min_mb:
            return False, f"Only {free_mb}MB free on / (need {min_mb}MB)"
        return True, f"{free_mb}MB free on /"
    except OSError as e:
        return False, f"Cannot check disk space: {e}"


def hold_packages(config: HeimdallConfig) -> list[str]:
    """Apply apt-mark hold on configured packages. Returns list of held packages."""
    held: list[str] = []
    if not shutil.which("apt-mark"):
        return held

    for pattern in config.policy.hold_packages:
        if "*" in pattern:
            # Resolve wildcard against installed packages
            stdout, _, rc = _run(["dpkg", "--get-selections"])
            if rc == 0:
                for line in stdout.splitlines():
                    parts = line.split()
                    if parts and parts[-1] == "install":
                        import fnmatch
                        if fnmatch.fnmatch(parts[0], pattern):
                            _run(["sudo", "apt-mark", "hold", parts[0]])
                            held.append(parts[0])
        else:
            _, _, rc = _run(["sudo", "apt-mark", "hold", pattern])
            if rc == 0:
                held.append(pattern)

    return held


def apply_apt_updates(packages: list[PendingUpdate]) -> UpdateResult:
    """Apply apt updates for the given packages."""
    result = UpdateResult()

    if not packages:
        result.success = True
        return result

    apt_packages = [u for u in packages if u.source == "apt"]
    if not apt_packages:
        result.success = True
        return result

    # Pre-check: disk space
    ok, msg = check_disk_space()
    result.log.append(f"Disk check: {msg}")
    if not ok:
        result.log.append("ABORT: insufficient disk space")
        result.skipped = [u.package for u in apt_packages]
        return result

    # Run apt update first
    stdout, stderr, rc = _run(["sudo", "apt", "update", "-qq"], timeout=120)
    if rc != 0:
        result.log.append(f"apt update failed: {stderr.strip()}")
        result.failed = [u.package for u in apt_packages]
        return result

    # Install specific packages
    pkg_names = [u.package for u in apt_packages]
    cmd = [
        "sudo", "apt", "install", "-y",
        "--only-upgrade",
        "-o", "Dpkg::Options::=--force-confold",
    ] + pkg_names

    result.log.append(f"Running: {' '.join(cmd)}")
    stdout, stderr, rc = _run(cmd, timeout=600)

    if rc == 0:
        result.success = True
        result.applied = pkg_names
        result.log.append("Updates applied successfully")
    else:
        result.success = False
        result.failed = pkg_names
        result.log.append(f"apt install failed (rc={rc}): {stderr.strip()}")

    return result


def apply_updates(packages: list[PendingUpdate], config: HeimdallConfig) -> UpdateResult:
    """Apply updates, dispatching by source."""
    # Hold configured packages first
    held = hold_packages(config)
    if held:
        pass  # Holds applied silently

    # For now, only apt is supported for auto-apply
    apt_packages = [u for u in packages if u.source == "apt"]
    non_apt = [u for u in packages if u.source != "apt"]

    result = apply_apt_updates(apt_packages)
    result.skipped.extend([u.package for u in non_apt])

    return result
