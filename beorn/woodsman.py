from __future__ import annotations
import subprocess
import shutil
from typing import Any, List, Optional
from beorn.engine import Bee, BeeResult


class WoodsmanBee(Bee):
    """The Woodsman (Auditd Integration) — Tracks footsteps via Linux Audit framework."""

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.ausearch_bin = shutil.which("ausearch")

    def collect(self) -> BeeResult:
        if not self.ausearch_bin:
            return BeeResult(
                success=False,
                summary="Woodsman: auditd tools not found",
                errors=["ausearch command not available"],
            )

        findings = []
        # Search for sudo executions in the last hour
        try:
            res = subprocess.run(
                [self.ausearch_bin, "-m", "USER_AUTH", "-ts", "recent", "-i"],
                capture_output=True,
                text=True,
            )
            if res.stdout:
                findings.append("Recent authentication events detected.")
        except Exception as e:
            return BeeResult(success=False, summary="Woodsman error", errors=[str(e)])

        return BeeResult(
            success=True,
            summary="Woodsman (Audit Mode): Tracking active"
            if findings
            else "No unusual tracks found",
            data={"audit_events": findings},
        )

    def pulse(self) -> Optional[BeeResult]:
        return self.collect()
