"""Report-retention policy: save a rule once, apply it later.

2026-08-26, per Dom: "a trim reports capability. I'm thinking two
modes: trim by time and trim by number so a tool that can take a
parameter like a time parameter (10 days, 10 weeks, 10 months) or a
number (10 reports) then these are remembered so you can later just
type 'purge reports' and the rule will be applied." Same "save once,
apply/reference later" shape this project already uses for
`risk_grade_scale` (module.py's `resolve_stored_params` /
`save_stored_scale`) -- just for cleaning up `output_dir` instead of
grading text, and with a JSON file on the same writable /data mount
instead of an encrypted one (a retention rule isn't a secret, same
tier as a saved risk_grade_scale).

Design decisions, all confirmed with Dom before building:
- Count unit: one report JOB (the .md+.html pair from one
  `submit_report_job` call) is one unit, always kept or deleted
  together -- never split across formats.
- Delete safety: `purge_reports` (in mcp_app.py) defaults to
  `dry_run=True` -- preview only, matching AGENT.md's Core Rules
  "require explicit confirmation immediately before any write" (a
  delete is a write).
- Scope: one global rule across every report module, not per-module.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

RETENTION_FILENAME = "report_retention.json"

_VALID_MODES = ("count", "days", "weeks", "months")

# Matches render.py's own filename convention exactly:
#   ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
#   base = job_dir / f"{ts}-{slug}"
# A file that doesn't start with this exact timestamp shape is not
# something this server wrote itself -- list_report_jobs skips it
# entirely, so purge_reports can never delete a file it doesn't
# recognize as its own output, no matter what rule is in force.
_TIMESTAMP_RE = re.compile(r"^(\d{8}T\d{6}Z)-")

# "months" has no fixed day count -- approximated as 30-day blocks,
# same tradeoff any simple retention tool makes. Documented here and
# in the tool description (mcp_app.py) rather than silently assumed.
_DAYS_PER_UNIT = {"days": 1, "weeks": 7, "months": 30}


@dataclass
class RetentionPolicy:
    mode: str  # "count" | "days" | "weeks" | "months"
    value: int

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> RetentionPolicy:
        return cls(mode=str(d["mode"]), value=int(d["value"]))


def validate_policy(mode: Any, value: Any) -> RetentionPolicy:
    mode_norm = str(mode).strip().lower()
    if mode_norm not in _VALID_MODES:
        raise ValueError(f"mode must be one of {_VALID_MODES}, got {mode!r}")
    try:
        value_int = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"value must be a positive integer, got {value!r}") from None
    if value_int <= 0:
        raise ValueError(f"value must be a positive integer, got {value!r}")
    return RetentionPolicy(mode=mode_norm, value=value_int)


class RetentionStore:
    """Reads/writes the saved retention policy under data_dir. Plain
    JSON (unlike config.py's Fernet-encrypted config.enc) -- a
    retention rule carries no secrets, so there's nothing here worth
    encrypting, same tier as a saved risk_grade_scale file."""

    def __init__(self, data_dir: Path) -> None:
        self.path = data_dir / RETENTION_FILENAME

    def load(self) -> RetentionPolicy | None:
        if not self.path.is_file():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            return RetentionPolicy.from_dict(raw)
        except (json.JSONDecodeError, KeyError, ValueError, TypeError) as e:
            raise ValueError(f"Saved retention policy at {self.path} is corrupt: {e}") from e

    def save(self, policy: RetentionPolicy) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(json.dumps(policy.to_dict(), indent=2, sort_keys=True), encoding="utf-8")


@dataclass
class ReportJob:
    """One report job -- whichever of its .md/.html files currently
    exist, grouped by the `<timestamp>-<slug>` base name render.py
    gives every format of the same job. Deleted as a single unit."""

    module: str
    base: str  # "<timestamp>-<slug>", no extension
    timestamp: datetime
    files: list[Path]


def list_report_jobs(output_dir: Path) -> list[ReportJob]:
    """Walks <output_dir>/<module>/<timestamp>-<slug>.{md,html} and
    groups files into one ReportJob per (module, base) pair, newest
    first. Any file whose name doesn't match render.py's own
    timestamp-prefix convention is skipped -- not grouped, not ever a
    deletion candidate."""
    if not output_dir.is_dir():
        return []
    jobs: dict[tuple[str, str], ReportJob] = {}
    for module_dir in sorted(p for p in output_dir.iterdir() if p.is_dir()):
        for f in sorted(module_dir.iterdir()):
            if not f.is_file():
                continue
            m = _TIMESTAMP_RE.match(f.name)
            if not m:
                continue
            try:
                ts = datetime.strptime(m.group(1), "%Y%m%dT%H%M%SZ").replace(tzinfo=UTC)
            except ValueError:
                continue
            key = (module_dir.name, f.stem)
            job = jobs.get(key)
            if job is None:
                job = ReportJob(module=module_dir.name, base=f.stem, timestamp=ts, files=[])
                jobs[key] = job
            job.files.append(f)
    return sorted(jobs.values(), key=lambda j: j.timestamp, reverse=True)


def plan_purge(
    jobs: list[ReportJob], policy: RetentionPolicy, *, now: datetime | None = None
) -> tuple[list[ReportJob], list[ReportJob]]:
    """Returns (to_keep, to_delete), both newest-first. `jobs` is
    expected pre-sorted newest-first (list_report_jobs already does
    this) -- count mode relies on that order directly."""
    if policy.mode == "count":
        return jobs[: policy.value], jobs[policy.value :]
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(days=policy.value * _DAYS_PER_UNIT[policy.mode])
    to_keep = [j for j in jobs if j.timestamp >= cutoff]
    to_delete = [j for j in jobs if j.timestamp < cutoff]
    return to_keep, to_delete


def apply_purge(to_delete: list[ReportJob]) -> list[str]:
    """Deletes every file belonging to each job in `to_delete`.
    Returns the deleted paths (as strings, for the audit log / tool
    result). A file already missing (e.g. manually cleaned up
    already) is skipped rather than erroring -- a partially-missing
    job shouldn't block deleting the rest of it."""
    deleted: list[str] = []
    for job in to_delete:
        for f in job.files:
            try:
                f.unlink()
                deleted.append(str(f))
            except FileNotFoundError:
                continue
    return deleted
