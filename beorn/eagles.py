from __future__ import annotations
import subprocess
import shutil
import re
from typing import Any, List, Optional, Dict
from beorn.engine import Bee, BeeResult
from beorn.state import StateManager


class EaglesBee(Bee):
    """The Eagles (Network Anomaly Detection) — Watching for unusual flights (connections)."""

    def __init__(self, name: str, config: Any, state_manager: StateManager):
        super().__init__(name, config)
        self.state_manager = state_manager
        self.ss_bin = shutil.which("ss") or shutil.which("netstat")

    def _get_active_connections(self) -> List[str]:
        if not self.ss_bin:
            return []

        try:
            # List established TCP/UDP connections
            res = subprocess.run([self.ss_bin, "-tun"], capture_output=True, text=True)
            lines = res.stdout.strip().split("\n")[1:]  # Skip header
            connections = []
            for line in lines:
                parts = re.split(r"\s+", line.strip())
                if len(parts) >= 5:
                    remote_ip_port = parts[4]
                    connections.append(remote_ip_port)
            return sorted(list(set(connections)))
        except Exception:
            return []

    def collect(self) -> BeeResult:
        if not self.ss_bin:
            return BeeResult(
                success=False,
                summary="Eagles: network tools missing",
                errors=["ss/netstat not found"],
            )

        current_flights = self._get_active_connections()
        safe_paths = self.state_manager.get_bee_state(self.name, "safe_paths") or []

        new_flights = [f for f in current_flights if f not in safe_paths]

        # In Audit Mode, we just alert on new flights and optionally auto-baseline them
        # (user should review these)
        if self.config.get("auto_baseline", True):
            # For now, update baseline to learn 'normal'
            self.state_manager.update_bee_state(
                self.name, "safe_paths", sorted(list(set(safe_paths + current_flights)))
            )

        status = f"Watching {len(current_flights)} active flights"
        if new_flights:
            status += f" ({len(new_flights)} new paths observed)"

        return BeeResult(
            success=True,
            summary=status,
            data={"new_paths": new_flights, "active_connections": len(current_flights)},
        )

    def pulse(self) -> Optional[BeeResult]:
        return self.collect()
