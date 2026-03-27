"""Update policy — decide what to auto-apply and what to hold."""

from __future__ import annotations

import fnmatch
from datetime import datetime
from typing import Optional

from beorn.config import BeornConfig
from beorn.scanner import PendingUpdate, ScanResult, UpdateType


def is_held(update: PendingUpdate, config: BeornConfig) -> bool:
    """Check if a package matches any hold pattern."""
    for pattern in config.policy.hold_packages:
        if fnmatch.fnmatch(update.package, pattern):
            return True
    return False


def in_maintenance_window(config: BeornConfig) -> bool:
    """Check if we're currently in the maintenance window."""
    now = datetime.now()
    return now.hour == config.policy.maintenance_hour


def get_auto_applicable(scan: ScanResult, config: BeornConfig) -> list[PendingUpdate]:
    """Return the list of updates that policy allows to auto-apply.

    Rules:
    1. Only security updates if auto_security is True
    2. Never held packages
    3. Only during maintenance window (unless security + critical)
    """
    if not config.policy.auto_security:
        return []

    applicable: list[PendingUpdate] = []
    for update in scan.updates:
        if is_held(update, config):
            continue
        if update.update_type == UpdateType.SECURITY:
            applicable.append(update)

    return applicable


def should_auto_apply_now(config: BeornConfig) -> bool:
    """Determine if auto-apply should run right now based on policy."""
    if not config.policy.auto_security:
        return False
    return in_maintenance_window(config)


def classify_scan(scan: ScanResult, config: BeornConfig) -> dict[str, list[PendingUpdate]]:
    """Classify all updates into action categories."""
    result: dict[str, list[PendingUpdate]] = {
        "auto_apply": [],
        "held": [],
        "manual": [],
    }

    for update in scan.updates:
        if is_held(update, config):
            result["held"].append(update)
        elif update.update_type == UpdateType.SECURITY and config.policy.auto_security:
            result["auto_apply"].append(update)
        else:
            result["manual"].append(update)

    return result
