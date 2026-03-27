from __future__ import annotations
import os
from typing import Any, List, Optional, Dict
from beorn.engine import Bee, BeeResult
from beorn.state import StateManager


class ElvenStarlightBee(Bee):
    """The Elven-Starlight (Log Pressure Monitor) — Watches for flashes (spikes) in auth/sys logs."""

    LOGS_TO_WATCH = [
        "/var/log/auth.log",
        "/var/log/syslog",
        "/var/log/nginx/access.log",
        "/var/log/apache2/access.log",
    ]

    def __init__(self, name: str, config: Any, state_manager: StateManager):
        super().__init__(name, config)
        self.state_manager = state_manager
        self.watch_logs = config.get("watch_logs", self.LOGS_TO_WATCH)

    def _get_log_size(self, path: str) -> Optional[int]:
        if not os.path.isfile(path):
            return None
        try:
            return os.path.getsize(path)
        except Exception:
            return None

    def collect(self) -> BeeResult:
        baseline_sizes = self.state_manager.get_bee_state(self.name, "log_sizes") or {}
        current_sizes = {}
        spikes = []
        errors = []

        for log in self.watch_logs:
            size = self._get_log_size(log)
            if size is None:
                continue

            current_sizes[log] = size
            if log in baseline_sizes:
                # If log grew significantly since last check (e.g. > 100KB in 5 mins)
                growth = size - baseline_sizes[log]
                if growth > self.config.get("spike_threshold_bytes", 102400):
                    spikes.append(
                        f"Significant growth detected in {log}: +{growth} bytes"
                    )
                elif growth < 0:
                    # Log rotation detected
                    pass

        self.state_manager.update_bee_state(self.name, "log_sizes", current_sizes)

        status = (
            "Log pressure stable"
            if not spikes
            else f"Detected {len(spikes)} log pressure spikes"
        )

        return BeeResult(
            success=True,
            summary=status,
            data={"spikes": spikes, "total_logs": len(current_sizes)},
            errors=errors,
        )

    def pulse(self) -> Optional[BeeResult]:
        return self.collect()
