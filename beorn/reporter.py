"""Report back to Mithrandir via HTTP API and Engram."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import requests

from beorn.config import BeornConfig, STATE_DIR
from beorn.scanner import ScanResult
from beorn.security import SecurityReport


REPORT_DIR = STATE_DIR / "reports"


def _build_report(
    config: BeornConfig,
    scan: ScanResult | None = None,
    security: SecurityReport | None = None,
) -> dict[str, Any]:
    """Build a structured report payload."""
    now = datetime.now(timezone.utc).isoformat()
    report: dict[str, Any] = {
        "hostname": config.hostname,
        "role": config.role,
        "timestamp": now,
        "scannedAt": now,
        "agent": "beorn",
        "version": "0.1.0",
    }

    if scan:
        report["updates"] = {
            "total": scan.total_count,
            "security": scan.security_count,
            "reboot_required": scan.reboot_required,
            "restart_services": scan.restart_services,
            "packages": [
                {
                    "name": u.package,
                    "current": u.current_version,
                    "new": u.new_version,
                    "source": u.source,
                    "type": u.update_type.value,
                }
                for u in scan.updates
            ],
            "errors": scan.errors,
        }

    if security:
        report["security"] = {
            "critical": security.critical_count,
            "warnings": security.warning_count,
            "findings": [
                {
                    "check": f.check,
                    "severity": f.severity.value,
                    "message": f.message,
                    "detail": f.detail,
                }
                for f in security.findings
            ],
            "errors": security.errors,
        }

    return report


def _build_engram_text(
    config: BeornConfig,
    scan: ScanResult | None = None,
    security: SecurityReport | None = None,
) -> str:
    """Build a human-readable text for Engram ingestion."""
    lines = [f"[HEIMDALL] {config.hostname} ({config.role}) — {datetime.now().strftime('%Y-%m-%d %H:%M')}"]

    if scan:
        lines.append(f"Updates: {scan.summary()}")
        if scan.security_count:
            sec_pkgs = [u.package for u in scan.updates if u.update_type.value == "security"]
            lines.append(f"  Security: {', '.join(sec_pkgs[:10])}")

    if security:
        lines.append(f"Security: {security.summary()}")
        for f in security.findings:
            if f.severity.value in ("critical", "warning"):
                lines.append(f"  [{f.severity.value.upper()}] {f.check}: {f.message}")

    return "\n".join(lines)


def report_to_mithrandir(
    config: BeornConfig,
    scan: ScanResult | None = None,
    security: SecurityReport | None = None,
) -> tuple[bool, str]:
    """Send report to Mithrandir's Gwaihir API."""
    if not config.mithrandir.api_key:
        return False, "No API key configured"

    url = f"{config.mithrandir.url.rstrip('/')}/api/beorn/report"
    payload = _build_report(config, scan, security)

    try:
        resp = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {config.mithrandir.api_key}",
                "Content-Type": "application/json",
            },
            timeout=30,
        )
        if resp.status_code < 300:
            return True, f"Reported to Mithrandir ({resp.status_code})"
        return False, f"Mithrandir returned {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"Failed to reach Mithrandir: {e}"


def report_to_engram(
    config: BeornConfig,
    scan: ScanResult | None = None,
    security: SecurityReport | None = None,
) -> tuple[bool, str]:
    """Log report to Engram via HTTP MCP endpoint."""
    if not config.mithrandir.engram_secret:
        return False, "No Engram secret configured"

    text = _build_engram_text(config, scan, security)
    url = config.mithrandir.engram_url

    # MCP-style JSON-RPC call to brain_ingest
    payload = {
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "brain_ingest",
            "arguments": {
                "content": text,
                "source_type": "agent",
                "source_agent": "claude",
                "tags": ["beorn", "security", config.hostname],
            },
        },
        "id": int(time.time()),
    }

    try:
        resp = requests.post(
            url,
            json=payload,
            headers={
                "Authorization": f"Bearer {config.mithrandir.engram_secret}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
            timeout=30,
        )
        if resp.status_code < 300:
            return True, "Logged to Engram"
        return False, f"Engram returned {resp.status_code}: {resp.text[:200]}"
    except requests.RequestException as e:
        return False, f"Failed to reach Engram: {e}"


def save_local_report(
    config: BeornConfig,
    scan: ScanResult | None = None,
    security: SecurityReport | None = None,
) -> Path:
    """Save report to local file as fallback."""
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = REPORT_DIR / f"report-{ts}.json"
    payload = _build_report(config, scan, security)
    path.write_text(json.dumps(payload, indent=2))
    return path


def send_report(
    config: BeornConfig,
    scan: ScanResult | None = None,
    security: SecurityReport | None = None,
) -> list[str]:
    """Send report to all configured destinations. Returns status messages."""
    messages: list[str] = []

    # Try Mithrandir
    ok, msg = report_to_mithrandir(config, scan, security)
    messages.append(f"Mithrandir: {msg}")

    # Try Engram
    ok, msg = report_to_engram(config, scan, security)
    messages.append(f"Engram: {msg}")

    # Always save locally
    path = save_local_report(config, scan, security)
    messages.append(f"Local: saved to {path}")

    return messages
