"""Local file storage for normalized OCSF events.

Events are appended as JSON Lines into date-partitioned directories derived
from the *event time* (not ingestion time - a backfill lands in the right
partition)::

    data/output/
    └── year=2026/
        └── month=09/
            └── day=24/
                ├── authentication.jsonl
                ├── account_change.jsonl
                ├── api_activity.jsonl
                └── network_activity.jsonl

Event-level failures and per-run summaries are stored alongside, under
``_errors/`` and ``_runs/``, so nothing is silently dropped.
"""

from __future__ import annotations

import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

logger = logging.getLogger("threatstream.storage.files")


def class_slug(class_name: str) -> str:
    """`Identity & Access`-style names -> stable lowercase file slug."""
    slug = class_name.lower().replace(" & ", "_and_").replace("&", " and ")
    slug = re.sub(r"[^a-z0-9]+", "_", slug).strip("_")
    return slug or "unknown"


def partition_parts(time_ms: int) -> tuple[str, str, str]:
    dt = datetime.fromtimestamp(time_ms / 1000, tz=timezone.utc)
    return f"year={dt.year:04d}", f"month={dt.month:02d}", f"day={dt.day:02d}"


class FileStorage:
    def __init__(self, output_dir: str | Path, errors_dir: str | Path | None = None, runs_dir: str | Path | None = None):
        self.output_dir = Path(output_dir)
        self.errors_dir = Path(errors_dir) if errors_dir else self.output_dir / "_errors"
        self.runs_dir = Path(runs_dir) if runs_dir else self.output_dir / "_runs"
        for d in (self.output_dir, self.errors_dir, self.runs_dir):
            d.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------ #
    def store_events(self, events: Iterable[Mapping[str, Any]]) -> int:
        """Append normalized events to per-class partition files. Returns count."""
        grouped: dict[Path, list[str]] = {}
        for event in events:
            slug = class_slug(str(event.get("class_name", "unknown")))
            try:
                parts = partition_parts(int(event.get("time", 0)))
            except (TypeError, ValueError):
                parts = partition_parts(0)
            path = self.output_dir.joinpath(*parts) / f"{slug}.jsonl"
            grouped.setdefault(path, []).append(json.dumps(event, default=str))

        stored = 0
        for path, lines in grouped.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            with path.open("a", encoding="utf-8") as fh:
                for line in lines:
                    fh.write(line + "\n")
            stored += len(lines)
            logger.info("Stored %d event(s) -> %s", len(lines), path)
        return stored

    # ------------------------------------------------------------------ #
    def store_errors(self, failures: Iterable[Mapping[str, Any]]) -> int:
        failures = list(failures)
        if not failures:
            return 0
        self.errors_dir.mkdir(parents=True, exist_ok=True)
        path = self.errors_dir / "pipeline_errors.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            for failure in failures:
                fh.write(json.dumps(failure, default=str) + "\n")
        logger.warning("Stored %d pipeline failure(s) -> %s", len(failures), path)
        return len(failures)

    # ------------------------------------------------------------------ #
    def store_run(self, summary: Mapping[str, Any]) -> Path:
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        path = self.runs_dir / "runs.jsonl"
        with path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(summary, default=str) + "\n")
        return path

    # ------------------------------------------------------------------ #
    def store_findings(self, findings: Iterable[Mapping[str, Any]]) -> int:
        """Append findings to _findings/findings.jsonl, skipping known ids."""
        findings = list(findings)
        if not findings:
            return 0
        path = self.output_dir / "_findings" / "findings.jsonl"
        path.parent.mkdir(parents=True, exist_ok=True)
        known: set[str] = set()
        if path.is_file():
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            known.add(str(json.loads(line).get("finding_id")))
                        except json.JSONDecodeError:
                            continue
        stored = 0
        with path.open("a", encoding="utf-8") as fh:
            for finding in findings:
                fid = str(finding.get("finding_id"))
                if fid in known:
                    continue
                fh.write(json.dumps(finding, default=str) + "\n")
                known.add(fid)
                stored += 1
        if stored:
            logger.info("Stored %d finding(s) -> %s", stored, path)
        return stored

    def iter_findings(self) -> Iterable[Mapping[str, Any]]:
        path = self.output_dir / "_findings" / "findings.jsonl"
        if not path.is_file():
            return
        with path.open(encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue

    # ------------------------------------------------------------------ #
    def iter_stored_events(self) -> Iterable[Mapping[str, Any]]:
        """Yield every stored normalized event (ignores _errors/_runs)."""
        for path in sorted(self.output_dir.rglob("*.jsonl")):
            if any(part.startswith("_") for part in path.relative_to(self.output_dir).parts[:-1]):
                continue
            if path.parent.name in {"_errors", "_runs"}:
                continue
            with path.open(encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            yield json.loads(line)
                        except json.JSONDecodeError:
                            continue
