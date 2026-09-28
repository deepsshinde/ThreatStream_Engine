"""API dependencies: optional PostgreSQL + file-fallback accessors."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.config import Settings, load_settings
from app.exceptions import ThreatStreamError
from app.storage.file_storage import FileStorage
from app.storage.postgres import PostgresStorage

logger = logging.getLogger("threatstream.api")


@dataclass
class AppState:
    """Request-scoped service container with graceful degradation."""

    settings: Settings
    _postgres: PostgresStorage | None = field(default=None, repr=False)
    _postgres_checked: bool = False

    def __post_init__(self):
        s = self.settings
        self.file = FileStorage(s.output_dir, errors_dir=s.errors_dir, runs_dir=s.runs_dir)

    @property
    def postgres(self) -> PostgresStorage | None:
        if not self._postgres_checked:
            self._postgres_checked = True
            if self.settings.postgres.enabled:
                try:
                    self._postgres = PostgresStorage(self.settings.postgres, self.settings.db_schema_file)
                except ThreatStreamError as exc:
                    logger.warning("API degraded: PostgreSQL unavailable (%s)", exc)
                    self._postgres = None
        return self._postgres

    # ------------------------------------------------------------------ #
    def events(self, filters: Mapping[str, Any], limit: int, offset: int):
        pg = self.postgres
        if pg is not None:
            return pg.query_events(filters, limit=limit, offset=offset)
        rows = list(self.file.iter_stored_events())
        # mirror DB filtering semantics over the file store
        def keep(ev: dict) -> bool:
            for key, want in (filters or {}).items():
                if want in (None, ""):
                    continue
                got = ev.get(key)
                if got is None and key == "src_ip":
                    got = (ev.get("src_endpoint") or {}).get("ip")
                if got is None and key == "actor_user":
                    got = ((ev.get("actor") or {}).get("user") or {}).get("name")
                if got is None and key in ("uid",):
                    got = (ev.get("metadata") or {}).get("uid")
                if got is None and key == "source_name":
                    got = (ev.get("metadata") or {}).get("log_source")
                if str(got) != str(want):
                    return False
            return True

        kept = [r for r in rows if keep(r)]
        items = [
            {
                "uid": (r.get("metadata") or {}).get("uid"),
                "time": r.get("time"),
                "class_name": r.get("class_name"),
                "activity_name": r.get("activity_name"),
                "severity": r.get("severity"),
                "status": r.get("status"),
                "source_name": (r.get("metadata") or {}).get("log_source"),
                "actor_user": ((r.get("actor") or {}).get("user") or {}).get("name"),
                "src_ip": (r.get("src_endpoint") or {}).get("ip"),
            }
            for r in kept
        ]
        items.sort(key=lambda r: r.get("time") or 0, reverse=True)
        return items[offset : offset + limit], len(items)

    def event_by_uid(self, uid: str) -> dict[str, Any] | None:
        pg = self.postgres
        if pg is not None:
            row = pg.fetch_event(uid)
            if row:
                return row
        for ev in self.file.iter_stored_events():
            if (ev.get("metadata") or {}).get("uid") == uid:
                return {"uid": uid, "event": ev}
        return None

    def findings(self, limit: int, offset: int, verdict: str | None, min_risk: int | None):
        pg = self.postgres
        if pg is not None:
            return pg.fetch_findings(limit=limit, offset=offset, verdict=verdict, min_risk=min_risk)
        rows = list(self.file.iter_findings())
        if verdict:
            rows = [r for r in rows if r.get("verdict") == verdict]
        if min_risk is not None:
            rows = [r for r in rows if int(r.get("risk_score") or 0) >= min_risk]
        rows.sort(key=lambda r: (r.get("risk_score") or 0), reverse=True)
        return rows[offset : offset + limit], len(rows)

    def finding_by_id(self, finding_id: str) -> dict[str, Any] | None:
        pg = self.postgres
        if pg is not None:
            row = pg.fetch_finding(finding_id)
            if row:
                return row
        for f in self.file.iter_findings():
            if f.get("finding_id") == finding_id:
                return f
        return None

    def stats(self) -> dict[str, Any]:
        pg = self.postgres
        if pg is not None:
            by_verdict = pg.findings_counts()
            return {
                "backend": "postgres",
                "totals": {"events": self._pg_total(pg)},
                "by_source": [{"key": k, "count": c} for k, c in pg.event_counts_by("source_name")],
                "by_class": [{"key": k, "count": c} for k, c in pg.event_counts_by("class_name")],
                "by_severity": [{"key": k, "count": c} for k, c in pg.event_counts_by("severity")],
                "failures": [
                    {"key": f"{src}:{status}", "count": n}
                    for src, status, n in pg.failures_by_source()
                ],
                "findings": {
                    "total": sum(n for _, n in by_verdict),
                    "by_verdict": [{"key": v, "count": n} for v, n in by_verdict],
                    "top_techniques": [{"key": t, "count": n} for t, n in pg.top_techniques()],
                },
            }
        # file fallback
        events = list(self.file.iter_stored_events())
        findings = list(self.file.iter_findings())
        from collections import Counter

        by_source = Counter((e.get("metadata") or {}).get("log_source") for e in events)
        by_class = Counter(e.get("class_name") for e in events)
        by_sev = Counter(e.get("severity") for e in events)
        verdicts = Counter(f.get("verdict") for f in findings)
        techniques: Counter = Counter()
        for f in findings:
            for t in f.get("mitre_techniques") or []:
                techniques[t.get("id")] += 1
        return {
            "backend": "files",
            "totals": {"events": len(events)},
            "by_source": [{"key": k, "count": c} for k, c in by_source.most_common()],
            "by_class": [{"key": k, "count": c} for k, c in by_class.most_common()],
            "by_severity": [{"key": k, "count": c} for k, c in by_sev.most_common()],
            "findings": {
                "total": len(findings),
                "by_verdict": [{"key": k, "count": c} for k, c in verdicts.most_common()],
                "top_techniques": [{"key": k, "count": c} for k, c in techniques.most_common(8)],
            },
        }

    @staticmethod
    def _pg_total(pg: PostgresStorage) -> int:
        return sum(c for _, c in pg.event_counts_by("source_name"))


def build_state(config_path: str | Path | None = None) -> AppState:
    return AppState(settings=load_settings(config_path))
