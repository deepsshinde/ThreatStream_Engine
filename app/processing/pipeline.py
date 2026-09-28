"""The ThreatStream processing pipeline.

Chains the Phase-1 stages end to end::

    raw record -> source detection -> OCSF mapping -> OCSF validation
               -> deduplication    -> partitioned file storage

Design rules:

* One bad event never kills a run - per-event failures are caught at the
  stage boundary, counted, and persisted to the errors store with the stage
  name, the error and a truncated event preview.
* Fingerprint-derived ``metadata.uid`` makes re-ingestion idempotent.
* Every run produces a :class:`PipelineSummary` which is printed for humans
  and appended to ``_runs/runs.jsonl`` for machines.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.config import Settings
from app.deduplication.deduplicator import Deduplicator
from app.detection.source_detector import SourceDetector
from app.exceptions import ThreatStreamError
from app.ingestion.file_reader import RawRecord, iter_directory_events, iter_file_events
from app.mapping.mapper import EventMapper
from app.mapping.mapping_loader import load_mappings
from app.processing.analysis import SecurityAnalyzer
from app.storage.file_storage import FileStorage
from app.storage.postgres import PostgresStorage
from app.validation.validator import OCSFValidator

logger = logging.getLogger("threatstream.pipeline")


def _preview(obj: Any, limit: int = 400) -> str:
    try:
        text = obj if isinstance(obj, str) else json.dumps(obj, default=str)
    except (TypeError, ValueError):
        text = repr(obj)
    return text[:limit]


@dataclass
class PipelineFailure:
    run_id: str
    stage: str
    error: str
    source_file: str | None = None
    source_name: str | None = None
    event_preview: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class PipelineSummary:
    run_id: str
    raw: int = 0
    detected: int = 0
    undetected: int = 0
    mapped: int = 0
    valid: int = 0
    invalid: int = 0
    duplicates: int = 0
    stored: int = 0
    stored_db: int | None = None  # rows actually inserted into PostgreSQL (None = DB disabled)
    signals: int | None = None   # deterministic correlation signals (None = analysis off)
    findings: int | None = None  # security findings produced+stored
    per_source: Counter = field(default_factory=Counter)
    per_class: Counter = field(default_factory=Counter)
    per_stage_failures: Counter = field(default_factory=Counter)
    duration_sec: float = 0.0
    errors_path: str | None = None

    @property
    def unique(self) -> int:
        return self.valid - self.duplicates

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "raw": self.raw,
            "detected": self.detected,
            "undetected": self.undetected,
            "mapped": self.mapped,
            "valid": self.valid,
            "invalid": self.invalid,
            "duplicates": self.duplicates,
            "unique": self.unique,
            "stored": self.stored,
            "stored_db": self.stored_db,
            "signals": self.signals,
            "findings": self.findings,
            "per_source": dict(self.per_source),
            "per_class": dict(self.per_class),
            "per_stage_failures": dict(self.per_stage_failures),
            "duration_sec": round(self.duration_sec, 3),
        }

    def render(self) -> str:
        bar = "=" * 52
        lines = [
            "",
            bar,
            "PIPELINE SUMMARY",
            bar,
            f"Run ID          : {self.run_id}",
            f"Raw events      : {self.raw}",
            f"Detected        : {self.detected}",
            f"Undetected      : {self.undetected}",
            f"Mapped          : {self.mapped}",
            f"Valid           : {self.valid}",
            f"Invalid         : {self.invalid}",
            f"Duplicates      : {self.duplicates}",
            f"Unique events   : {self.unique}",
            f"Stored          : {self.stored}",
        ]
        if self.stored_db is not None:
            lines.append(f"Stored (Postgres): {self.stored_db}")
        if self.signals is not None:
            lines.append(f"Security signals : {self.signals}")
            lines.append(f"Security findings: {self.findings}")
        if self.per_stage_failures:
            lines.append("Failures        : " + ", ".join(f"{k}={v}" for k, v in sorted(self.per_stage_failures.items())))
            if self.errors_path:
                lines.append(f"Errors stored at: {self.errors_path}")
        if self.per_source:
            lines += ["", "Events by source:"]
            lines += [f"  {name:<22} : {count}" for name, count in self.per_source.most_common()]
        if self.per_class:
            lines += ["", "Events by OCSF class:"]
            lines += [f"  {name:<22} : {count}" for name, count in self.per_class.most_common()]
        lines += ["", f"Duration        : {self.duration_sec:.2f} sec", bar, ""]
        return "\n".join(lines)


class ThreatStreamPipeline:
    """Composable Phase-1 batch pipeline (also reused by the Kafka consumer in Phase 3)."""

    def __init__(self, settings: Settings):
        self.settings = settings
        settings.ensure_directories()
        configs = load_mappings(settings.mappings_dir)
        self.detector = SourceDetector(configs)
        self.mapper = EventMapper(configs)
        self.validator = OCSFValidator()
        self.deduplicator = Deduplicator(
            window_minutes=settings.dedup_window_minutes,
            enabled=settings.dedup_enabled,
            state_path=settings.dedup_state_file if settings.dedup_persist else None,
        )
        self.storage = FileStorage(
            settings.output_dir,
            errors_dir=settings.errors_dir,
            runs_dir=settings.runs_dir,
        )
        # Security analysis (correlation + RAG + LLM) is optional but degradable.
        self.analyzer: SecurityAnalyzer | None = None
        if settings.analysis.enabled:
            try:
                self.analyzer = SecurityAnalyzer(settings)
            except ThreatStreamError as exc:
                logger.warning("Security analysis disabled: %s", exc)

        # PostgreSQL is optional: unreachable DB -> degraded file-only mode.
        self.postgres: PostgresStorage | None = None
        if settings.postgres.enabled:
            try:
                self.postgres = PostgresStorage(settings.postgres, settings.db_schema_file)
                self.postgres.init_schema()
                logger.info("PostgreSQL storage enabled (%s)", settings.postgres.describe)
            except ThreatStreamError as exc:
                logger.warning("PostgreSQL unavailable, continuing file-only: %s", exc)
                self.postgres = None

    def _pg_call(self, operation: str, *args):
        """Run a named PostgreSQL operation defensively; a DB hiccup never kills a run."""
        if self.postgres is None:
            return None
        try:
            return getattr(self.postgres, operation)(*args)
        except Exception as exc:
            logger.warning("PostgreSQL %s failed (continuing file-only): %s", operation, exc)
            return None

    def close(self) -> None:
        self.deduplicator.close()
        if self.postgres is not None:
            self.postgres.close()

    # ------------------------------------------------------------------ #
    def process_file(self, path: str | Path) -> PipelineSummary:
        logger.info("Processing file %s", path)
        return self.process_records(iter_file_events(path))

    def process_directory(self, directory: str | Path) -> PipelineSummary:
        logger.info("Processing directory %s", directory)
        return self.process_records(iter_directory_events(directory))

    # ------------------------------------------------------------------ #
    def process_records(self, records: Iterable[RawRecord | Mapping[str, Any]]) -> PipelineSummary:
        run_id = uuid.uuid4().hex[:12]
        summary = PipelineSummary(run_id=run_id)
        failures: list[PipelineFailure] = []
        valid_events: list[dict[str, Any]] = []
        started = time.perf_counter()
        logger.info("Pipeline run %s started", run_id)

        def fail(stage: str, error: str, record: RawRecord, source_name: str | None = None) -> None:
            preview = record.raw_text if record.raw_text else _preview(record.event or {})
            failures.append(PipelineFailure(run_id, stage, error, record.source_file, source_name, _preview(preview)))
            summary.per_stage_failures[stage] += 1
            logger.warning("stage=%s event dropped: %s (%s:%s)", stage, error, record.source_file, record.line)

        for record in records:
            if isinstance(record, Mapping) and not isinstance(record, RawRecord):
                record = RawRecord(source_file="<stream>", event=dict(record))
            summary.raw += 1

            if record.error:
                fail("ingestion", record.error, record)
                continue

            event = record.event
            if event is None:
                fail("ingestion", "no event payload", record)
                continue

            detection = self.detector.detect(event)
            if detection is None:
                summary.undetected += 1
                fail("detection", "unknown log source", record)
                continue
            source = detection.source_name
            summary.detected += 1
            summary.per_source[source] += 1
            logger.info("Detected source=%s file=%s", source, record.source_file)

            try:
                mapped = self.mapper.map_event(event, source)
            except Exception as exc:
                fail("mapping", str(exc), record, source_name=source)
                continue
            summary.mapped += 1
            logger.debug("Mapped event -> class=%s activity=%s", mapped.get("class_name"), mapped.get("activity_name"))

            result = self.validator.validate(mapped)
            if not result.valid:
                summary.invalid += 1
                fail("validation", "; ".join(result.errors), record, source_name=source)
                continue
            summary.valid += 1

            is_dup, fingerprint = self.deduplicator.is_duplicate(mapped)
            if is_dup:
                summary.duplicates += 1
                logger.info("Duplicate event uid=%s skipped", fingerprint[:12])
                continue

            mapped["metadata"]["uid"] = fingerprint
            valid_events.append(mapped)
            summary.per_class[mapped["class_name"]] += 1

        summary.stored = self.storage.store_events(valid_events)
        # PostgreSQL dual-write (idempotent: uid UNIQUE + ON CONFLICT DO NOTHING).
        # _pg_call returns None when the DB is disabled or the write failed.
        summary.stored_db = self._pg_call("store_events", valid_events, run_id)
        self.deduplicator.close()

        if failures:
            failure_dicts = [f.to_dict() for f in failures]
            self.storage.store_errors(failure_dicts)
            self._pg_call("store_errors", failure_dicts)
            summary.errors_path = str(self.storage.errors_dir / "pipeline_errors.jsonl")

        # Security analysis: correlation signals + RAG/LLM findings over this
        # run's unique valid events. A failure here never invalidates the run -
        # events are already stored.
        if self.analyzer is not None and valid_events:
            try:
                analysis = self.analyzer.analyze_events(valid_events)
                summary.signals = len(analysis.signals)
                finding_rows = [f.to_row() for f in analysis.findings]
                summary.findings = self.storage.store_findings(finding_rows)
                self._pg_call("store_findings", finding_rows)
                logger.info(
                    "Analysis: %d signals, %d findings (engine=%s, retrieval=%s)",
                    len(analysis.signals), summary.findings,
                    analysis.engine_used, analysis.retrieval_available,
                )
            except Exception as exc:
                logger.warning("Security analysis failed (events already stored): %s", exc)
                summary.signals = summary.findings = None

        summary.duration_sec = time.perf_counter() - started
        self.storage.store_run(summary.to_dict())
        self._pg_call("store_run", summary.to_dict())
        logger.info("Pipeline run %s finished: %s", run_id, summary.to_dict())
        return summary
