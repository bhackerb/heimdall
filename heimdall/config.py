"""Configuration loading from YAML with sensible defaults."""

from __future__ import annotations

import os
import socket
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


CONFIG_DIR = Path.home() / ".config" / "heimdall"
CONFIG_PATH = CONFIG_DIR / "config.yaml"
STATE_DIR = CONFIG_DIR / "state"


@dataclass
class MithrandirConfig:
    url: str = "https://gwaihir.bhackerb.com"
    api_key: str = ""
    engram_url: str = "https://engram.bhackerb.com/mcp"
    engram_secret: str = ""


@dataclass
class ScheduleConfig:
    update_scan_hours: int = 6
    security_scan_hours: int = 12
    report_hours: int = 24


@dataclass
class PolicyConfig:
    auto_security: bool = True
    hold_packages: list[str] = field(default_factory=lambda: [
        "nvidia-*", "linux-image-*", "postgresql-*", "docker-ce",
    ])
    maintenance_hour: int = 3


@dataclass
class SecurityConfig:
    check_ufw: bool = True
    check_fail2ban: bool = True
    check_ssh_config: bool = True
    check_open_ports: bool = True
    check_listening_services: bool = True
    alert_on_new_port: bool = True


@dataclass
class HeimdallConfig:
    hostname: str = ""
    role: str = "workstation"
    mithrandir: MithrandirConfig = field(default_factory=MithrandirConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    policy: PolicyConfig = field(default_factory=PolicyConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    def __post_init__(self) -> None:
        if not self.hostname:
            self.hostname = socket.gethostname()


def _merge_dataclass(dc: Any, data: dict[str, Any]) -> None:
    """Merge a dict into a dataclass, ignoring unknown keys."""
    for key, value in data.items():
        if hasattr(dc, key):
            setattr(dc, key, value)


def load_config(path: Path | None = None) -> HeimdallConfig:
    """Load configuration from YAML file, falling back to defaults."""
    path = path or CONFIG_PATH
    cfg = HeimdallConfig()

    if not path.exists():
        return cfg

    with open(path) as f:
        raw: dict[str, Any] = yaml.safe_load(f) or {}

    if "hostname" in raw:
        cfg.hostname = raw["hostname"]
    if "role" in raw:
        cfg.role = raw["role"]
    if "mithrandir" in raw and isinstance(raw["mithrandir"], dict):
        _merge_dataclass(cfg.mithrandir, raw["mithrandir"])
    if "schedule" in raw and isinstance(raw["schedule"], dict):
        _merge_dataclass(cfg.schedule, raw["schedule"])
    if "policy" in raw and isinstance(raw["policy"], dict):
        _merge_dataclass(cfg.policy, raw["policy"])
    if "security" in raw and isinstance(raw["security"], dict):
        _merge_dataclass(cfg.security, raw["security"])

    # Environment overrides (useful for systemd)
    if env_key := os.environ.get("HEIMDALL_API_KEY"):
        cfg.mithrandir.api_key = env_key
    if env_secret := os.environ.get("HEIMDALL_ENGRAM_SECRET"):
        cfg.mithrandir.engram_secret = env_secret

    return cfg


def ensure_dirs() -> None:
    """Create config and state directories if they don't exist."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    STATE_DIR.mkdir(parents=True, exist_ok=True)
