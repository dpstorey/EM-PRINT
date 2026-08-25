"""Append-only audit log for report jobs.

Phase 0: local JSONL only, same baseline as EM-MCP's audit.py today
(EM-MCP does not currently ship to syslog either — that's new work,
not something to reuse as-is). Phase 4 adds syslog-over-TLS shipping
and tamper-evident handling of destination changes; see design-notes.md
§4.2. Keep this class's public shape stable so that Phase 4 can slot a
syslog sink in behind `record()` without touching call sites.
"""

from __future__ import annotations

import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

AUDIT_FILENAME = "audit.jsonl"


class AuditLog:
    """Thread-safe append-only writer."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / AUDIT_FILENAME
        self._lock = threading.Lock()
        data_dir.mkdir(parents=True, exist_ok=True)

    def record(
        self,
        *,
        event: str,
        module: str | None = None,
        params: dict[str, Any] | None = None,
        outcome: str,
        output_paths: list[str] | None = None,
        error: str | None = None,
    ) -> None:
        """Write one audit row.

        Args:
            event: e.g. 'report_job_submitted', 'report_job_completed'.
            module: report module name, when applicable.
            params: job parameters (already redacted of secrets by the caller).
            outcome: 'ok' | 'error'.
            output_paths: rendered file paths, when the job succeeded.
            error: error message when outcome != 'ok'.
        """
        row: dict[str, Any] = {
            "ts": datetime.now(UTC).isoformat(),
            "event": event,
            "outcome": outcome,
        }
        if module:
            row["module"] = module
        if params:
            row["params"] = params
        if output_paths:
            row["output_paths"] = output_paths
        if error:
            row["error"] = error
        line = json.dumps(row, default=str, sort_keys=True) + "\n"
        with self._lock, self.path.open("a", encoding="utf-8") as f:
            f.write(line)

    def recent(self, limit: int = 20) -> list[dict[str, Any]]:
        """Return up to `limit` most recent audit rows, newest first.

        Best-effort: a missing file returns an empty list, and any
        line that fails to parse (e.g. a read caught mid-append) is
        skipped rather than raised. This is a read path bolted onto
        an append-only log for `list_recent_report_jobs` -- Phase 0
        has no separate job-status store yet (see design-notes.md),
        so "is my job done" is answered by "does the audit log have a
        completed/error row for it" rather than a true running/queued
        state.
        """
        if not self.path.is_file():
            return []
        with self._lock, self.path.open("r", encoding="utf-8") as f:
            lines = f.readlines()
        rows: list[dict[str, Any]] = []
        for raw_line in reversed(lines):
            raw_line = raw_line.strip()
            if not raw_line:
                continue
            try:
                rows.append(json.loads(raw_line))
            except json.JSONDecodeError:
                continue
            if len(rows) >= limit:
                break
        return rows
