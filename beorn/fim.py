from __future__ import annotations
import os
import hashlib
from pathlib import Path
from typing import Dict, List, Optional, Any
from beorn.engine import Bee, BeeResult
from beorn.state import StateManager


class FIMBee(Bee):
    """The File Integrity Monitoring (FIM) Bee — watches critical paths."""

    DEFAULT_WATCH_PATHS = [
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/crontab",
    ]

    def __init__(self, name: str, config: Any, state_manager: StateManager):
        super().__init__(name, config)
        self.state_manager = state_manager
        self.watch_paths = config.get("watch_paths", self.DEFAULT_WATCH_PATHS)

    def _hash_file(self, path: str) -> Optional[str]:
        if not os.path.isfile(path):
            return None
        try:
            sha256_hash = hashlib.sha256()
            with open(path, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except Exception as e:
            return None

    def collect(self) -> BeeResult:
        """Full scan — check current hashes against baseline."""
        baseline = self.state_manager.get_bee_state(self.name, "hashes") or {}
        current_hashes = {}
        changes = []
        errors = []

        for path in self.watch_paths:
            h = self._hash_file(path)
            if h is None:
                errors.append(f"Could not read: {path}")
                continue

            current_hashes[path] = h
            if path in baseline:
                if baseline[path] != h:
                    changes.append(f"MODIFIED: {path}")
            else:
                changes.append(f"NEW WATCHED FILE: {path}")

        self.state_manager.update_bee_state(self.name, "hashes", current_hashes)

        status = "No changes" if not changes else f"Detected {len(changes)} changes"
        return BeeResult(
            success=True,
            summary=status,
            data={"changes": changes, "total_watched": len(self.watch_paths)},
            errors=errors,
        )

    def pulse(self) -> Optional[BeeResult]:
        """Lightweight pulse — check if critical files have changed recently."""
        # Simple implementation: check modification times or just do a quick hash.
        # For Beorn, we'll keep it as a quick hash for now.
        return self.collect()
