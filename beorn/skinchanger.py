from __future__ import annotations
import os
import shutil
import subprocess
from typing import Any, List, Optional, Dict
from beorn.engine import Bee, BeeResult


class SkinChangerBee(Bee):
    """The Skin-Changer (Process Watcher) — Tracking process mutations and unusual parents."""

    # Common tools attackers use for 'living off the land'
    SUSPICIOUS_TOOLS = [
        "python",
        "perl",
        "bash",
        "sh",
        "nc",
        "socat",
        "base64",
        "curl",
        "wget",
    ]

    def __init__(self, name: str, config: Any):
        super().__init__(name, config)
        self.ps_bin = shutil.which("ps")

    def _get_suspicious_processes(self) -> List[Dict[str, str]]:
        if not self.ps_bin:
            return []

        try:
            # List all processes with user and full command line
            res = subprocess.run(
                [self.ps_bin, "-eo", "user,pid,ppid,comm,args", "--no-headers"],
                capture_output=True,
                text=True,
            )
            processes = []
            for line in res.stdout.strip().split("\n"):
                parts = line.split(None, 4)
                if len(parts) < 5:
                    continue
                user, pid, ppid, comm, args = parts

                # Simple Audit Check:
                # 1. Is it a suspicious tool?
                # 2. Is it running as root?
                # 3. Does it have a shell parent but not interactive?

                for tool in self.SUSPICIOUS_TOOLS:
                    if tool in comm.lower() or tool in args.lower():
                        processes.append(
                            {
                                "user": user,
                                "pid": pid,
                                "ppid": ppid,
                                "comm": comm,
                                "command": args,
                            }
                        )
                        break
            return processes
        except Exception:
            return []

    def collect(self) -> BeeResult:
        if not self.ps_bin:
            return BeeResult(
                success=False,
                summary="Skin-Changer: process tools missing",
                errors=["ps not found"],
            )

        suspicious = self._get_suspicious_processes()

        status = (
            f"Skin-Changer (Audit Mode): Monitoring {len(suspicious)} tracked skins"
        )

        return BeeResult(
            success=True,
            summary=status,
            data={"suspicious_processes": suspicious, "total_tracked": len(suspicious)},
        )

    def pulse(self) -> Optional[BeeResult]:
        return self.collect()
