"""PostgreSQL storage for normalized events, failures, runs and findings.

Design notes:

* **Plain psycopg 3 + real SQL** (ddl in ``db/schema.sql``) - deliberately no
  ORM: the SQL is the portfolio artifact and keeps the dependency tree small.
* **Idempotent by construction.** ``normalized_events.uid`` is the SHA-256
  content fingerprint from the dedup stage, so
  ``INSERT ... ON CONFLICT (uid) DO NOTHING`` makes replayed runs free -
  re-ingesting the same Kafka messages / files inserts 0 rows.
* **Optional & defensive.** If psycopg is missing or the DB is unreachable,
  :class:`PostgresUnavailable` is raised; the pipeline catches it and keeps
  running in file-only mode with a warning.
* **Query columns + JSONB.** Hot filter fields are typed columns with B-tree
  indexes; the full OCSF document sits in a GIN-indexed JSONB column.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Mapping

from app.config import PostgresSettings
from app.exceptions import PostgresUnavailable

logger = logging.getLogger("threatstream.storage.postgres")

try:  # psycopg is an optional dependency (file-only installs skip it)
    import psycopg
    from psycopg.rows import dict_row
    from psycopg.types.json import Jsonb

    HAVE_PSYCOPG = True
except ImportError:  # pragma: no cover - depends on environment
    psycopg = None
    dict_row = None
    Jsonb = None
    HAVE_PSYCOPG = False

TABLES = ("normalized_events", "validation_errors", "security_findings", "processing_runs")

# Whitelist for group-by queries (never interpolate user input into SQL otherwise)
_GROUPABLE = {"source_name", "class_name", "severity", "src_ip", "actor_user", "status"}

_INSERT_EVENT = """
INSERT INTO normalized_events
    (uid, time, class_uid, class_name, category_uid, activity_id, activity_name,
     severity_id, severity, status_id, status, source_name, actor_user, src_ip,
     run_id, event)
VALUES
    (%(uid)s, %(time)s, %(class_uid)s, %(class_name)s, %(category_uid)s,
     %(activity_id)s, %(activity_name)s, %(severity_id)s, %(severity)s,
     %(status_id)s, %(status)s, %(source_name)s, %(actor_user)s, %(src_ip)s,
     %(run_id)s, %(event)s)
ON CONFLICT (uid) DO NOTHING
"""

_INSERT_ERROR = """
INSERT INTO validation_errors (run_id, stage, error, source_file, source_name, event_preview)
VALUES (%(run_id)s, %(stage)s, %(error)s, %(source_file)s, %(source_name)s, %(event_preview)s)
"""

_INSERT_FINDING = """
INSERT INTO security_findings
    (finding_id, event_uid, correlation_id, verdict, risk_score, summary,
     signals, mitre_techniques, recommendations, llm_used)
VALUES
    (%(finding_id)s, %(event_uid)s, %(correlation_id)s, %(verdict)s, %(risk_score)s,
     %(summary)s, %(signals)s, %(mitre_techniques)s, %(recommendations)s, %(llm_used)s)
ON CONFLICT (finding_id) DO NOTHING
"""

_INSERT_RUN = """
INSERT INTO processing_runs
    (run_id, duration_sec, raw, detected, undetected, mapped, valid, invalid,
     duplicates, unique_events, stored, stored_db,
     per_source, per_class, per_stage_failures, summary)
VALUES
    (%(run_id)s, %(duration_sec)s, %(raw)s, %(detected)s, %(undetected)s,
     %(mapped)s, %(valid)s, %(invalid)s, %(duplicates)s, %(unique_events)s,
     %(stored)s, %(stored_db)s,
     %(per_source)s, %(per_class)s, %(per_stage_failures)s, %(summary)s)
ON CONFLICT (run_id) DO NOTHING
"""


class PostgresStorage:
    def __init__(self, pg: PostgresSettings, schema_path: str | Path):
        if not HAVE_PSYCOPG:
            raise PostgresUnavailable(
                "psycopg is not installed (pip install 'psycopg[binary]')"
            )
        self.pg = pg
        self.schema_path = Path(schema_path)
        self._conn = None

    # ------------------------------------------------------------------ #
    # connection lifecycle
    # ------------------------------------------------------------------ #
    def _connection(self):
        if self._conn is None or self._conn.closed:
            try:
                self._conn = psycopg.connect(self.pg.conninfo, autocommit=False)
                # Defense-in-depth: on SQL_ASCII clusters psycopg3 returns
                # ``bytes`` for text columns. Docker postgres images are UTF8
                # by default, but make text decoding deterministic regardless.
                self._conn.execute("SET client_encoding TO 'UTF8'")
                self._conn.commit()
            except Exception as exc:
                raise PostgresUnavailable(
                    f"cannot connect to PostgreSQL ({self.pg.describe}): {exc}"
                ) from exc
        return self._conn

    def ping(self) -> bool:
        try:
            conn = self._connection()
            with conn.cursor() as cur:
                cur.execute("SELECT 1")
            return True
        except Exception:
            return False

    def close(self) -> None:
        if self._conn is not None and not self._conn.closed:
            self._conn.close()

    # ------------------------------------------------------------------ #
    # schema
    # ------------------------------------------------------------------ #
    def init_schema(self) -> list[str]:
        """Apply db/schema.sql (idempotent). Returns managed table names."""
        ddl = self.schema_path.read_text(encoding="utf-8")
        cleaned = "\n".join(
            line for line in ddl.splitlines() if not line.strip().startswith("--")
        )
        statements = [s.strip() for s in cleaned.split(";") if s.strip()]
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                for stmt in statements:
                    cur.execute(stmt)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.info("Schema applied (%d statements) -> %s", len(statements), ", ".join(TABLES))
        return sorted(TABLES)

    # ------------------------------------------------------------------ #
    # writes
    # ------------------------------------------------------------------ #
    def store_events(self, events: Iterable[Mapping[str, Any]], run_id: str | None = None) -> int:
        """Insert events, skipping uids already present. Returns rows inserted."""
        rows = [self._event_row(e, run_id) for e in events]
        if not rows:
            return 0
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.executemany(_INSERT_EVENT, rows)
                inserted = max(cur.rowcount, 0)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        logger.debug("Inserted %d/%d events into PostgreSQL", inserted, len(rows))
        return inserted

    def store_errors(self, failures: Iterable[Mapping[str, Any]]) -> int:
        rows = [
            {
                "run_id": f.get("run_id"),
                "stage": f.get("stage", "unknown"),
                "error": str(f.get("error", ""))[:2000],
                "source_file": f.get("source_file"),
                "source_name": f.get("source_name"),
                "event_preview": f.get("event_preview"),
            }
            for f in failures
        ]
        if not rows:
            return 0
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.executemany(_INSERT_ERROR, rows)
                inserted = max(cur.rowcount, 0)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return inserted

    def store_run(self, summary: Mapping[str, Any]) -> None:
        row = {
            "run_id": summary.get("run_id"),
            "duration_sec": summary.get("duration_sec"),
            "raw": summary.get("raw"),
            "detected": summary.get("detected"),
            "undetected": summary.get("undetected"),
            "mapped": summary.get("mapped"),
            "valid": summary.get("valid"),
            "invalid": summary.get("invalid"),
            "duplicates": summary.get("duplicates"),
            "unique_events": summary.get("unique"),
            "stored": summary.get("stored"),
            "stored_db": summary.get("stored_db"),
            "per_source": Jsonb(summary.get("per_source") or {}),
            "per_class": Jsonb(summary.get("per_class") or {}),
            "per_stage_failures": Jsonb(summary.get("per_stage_failures") or {}),
            "summary": Jsonb(dict(summary)),
        }
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.execute(_INSERT_RUN, row)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def store_findings(self, findings: Iterable[Mapping[str, Any]]) -> int:
        rows = [dict(f) for f in findings]
        if not rows:
            return 0
        for row in rows:
            for key in ("signals", "mitre_techniques", "recommendations"):
                row[key] = Jsonb(row.get(key) or [])
        conn = self._connection()
        try:
            with conn.cursor() as cur:
                cur.executemany(_INSERT_FINDING, rows)
                inserted = max(cur.rowcount, 0)
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return inserted

    # ------------------------------------------------------------------ #
    # reads (used by CLI stats now, API in Phase 7)
    # ------------------------------------------------------------------ #
    def fetch_event(self, uid: str) -> dict[str, Any] | None:
        conn = self._connection()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute("SELECT * FROM normalized_events WHERE uid = %s", (uid,))
            row = cur.fetchone()
        return dict(row) if row else None

    def recent_events(self, limit: int = 20) -> list[dict[str, Any]]:
        conn = self._connection()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT uid, time, class_name, activity_name, severity, status, "
                "source_name, actor_user, src_ip FROM normalized_events "
                "ORDER BY time DESC LIMIT %s",
                (limit,),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    def count_events(self) -> int:
        return int(self._scalar("SELECT count(*) FROM normalized_events"))

    def count_errors(self) -> int:
        return int(self._scalar("SELECT count(*) FROM validation_errors"))

    def count_runs(self) -> int:
        return int(self._scalar("SELECT count(*) FROM processing_runs"))

    def count_findings(self) -> int:
        return int(self._scalar("SELECT count(*) FROM security_findings"))

    def recent_runs(self, limit: int = 5) -> list[dict[str, Any]]:
        conn = self._connection()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT run_id, created_at, raw, valid, duplicates, stored, stored_db, duration_sec "
                "FROM processing_runs ORDER BY created_at DESC LIMIT %s",
                (limit,),
            )
            rows = cur.fetchall()
        return [dict(r) for r in rows]

    # whitelist of filterable event columns for API queries
    _EVENT_FILTERS = {"source_name", "class_name", "severity", "status", "src_ip", "actor_user", "uid"}

    def query_events(
        self, filters: Mapping[str, Any] | None = None, limit: int = 50, offset: int = 0
    ) -> tuple[list[dict[str, Any]], int]:
        """Filtered, paginated event list. Returns (rows, total_count).

        Filter keys are whitelisted; values are parameterized - never interpolated.
        """
        where, params = [], []
        for key, value in (filters or {}).items():
            if key not in self._EVENT_FILTERS or value in (None, ""):
                continue
            where.append(f"{key} = %s")
            params.append(str(value))
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        conn = self._connection()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT count(*) FROM normalized_events {clause}", params)
            total = int(cur.fetchone()["count"])
            cur.execute(
                f"SELECT uid, time, class_name, activity_name, severity, status, "
                f"source_name, actor_user, src_ip FROM normalized_events {clause} "
                f"ORDER BY time DESC LIMIT %s OFFSET %s",
                [*params, limit, offset],
            )
            rows = [dict(r) for r in cur.fetchall()]
        return rows, total

    def fetch_findings(
        self,
        limit: int = 50,
        offset: int = 0,
        verdict: str | None = None,
        min_risk: int | None = None,
    ) -> tuple[list[dict[str, Any]], int]:
        where, params = [], []
        if verdict:
            where.append("verdict = %s")
            params.append(verdict)
        if min_risk is not None:
            where.append("risk_score >= %s")
            params.append(int(min_risk))
        clause = f"WHERE {' AND '.join(where)}" if where else ""
        conn = self._connection()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(f"SELECT count(*) FROM security_findings {clause}", params)
            total = int(cur.fetchone()["count"])
            cur.execute(
                f"SELECT id, finding_id, event_uid, correlation_id, verdict, risk_score, "
                f"summary, signals, mitre_techniques, recommendations, llm_used, created_at "
                f"FROM security_findings {clause} ORDER BY risk_score DESC, created_at DESC "
                f"LIMIT %s OFFSET %s",
                [*params, limit, offset],
            )
            rows = [dict(r) for r in cur.fetchall()]
        return rows, total

    def fetch_finding(self, finding_id: str) -> dict[str, Any] | None:
        conn = self._connection()
        with conn.cursor(row_factory=dict_row) as cur:
            cur.execute(
                "SELECT * FROM security_findings WHERE finding_id = %s", (finding_id,)
            )
            row = cur.fetchone()
        return dict(row) if row else None

    def top_techniques(self, limit: int = 8) -> list[tuple[str, int]]:
        """Flatten finding technique references and count them (JSONB -> SQL)."""
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT tech->>'id' AS technique_id, count(*)
                FROM security_findings,
                     LATERAL jsonb_array_elements(mitre_techniques) AS tech
                GROUP BY 1
                ORDER BY 2 DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
        return [(str(t), int(c)) for t, c in rows]

    def count_by(self, column: str) -> list[tuple[str, int]]:
        """Group-by counts over whitelisted columns only."""
        if column not in _GROUPABLE:
            raise ValueError(f"cannot group by '{column}'; allowed: {sorted(_GROUPABLE)}")
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(
                f"SELECT COALESCE({column}::text, 'unknown') AS key, count(*) "
                f"FROM normalized_events GROUP BY {column} ORDER BY 2 DESC"
            )
            rows = cur.fetchall()
        return [(str(k), int(c)) for k, c in rows]

    def event_counts_by(self, column: str) -> list[tuple[str, int]]:
        return self.count_by(column)

    def failures_by_source(self) -> list[tuple[str, str, int]]:
        """Per-source per-status event counts (used by stats and the dashboard)."""
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT COALESCE(source_name,'unknown'), COALESCE(status,'unknown'), count(*) "
                "FROM normalized_events GROUP BY 1, 2 ORDER BY 1, 3 DESC"
            )
            rows = cur.fetchall()
        return [(str(s), t, int(n)) for s, t, n in rows]

    def findings_counts(self) -> list[tuple[str, int]]:
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT verdict, count(*) FROM security_findings GROUP BY verdict ORDER BY 2 DESC"
            )
            rows = cur.fetchall()
        return [(str(v), int(n)) for v, n in rows]

    # ------------------------------------------------------------------ #
    def _scalar(self, query: str) -> int:
        conn = self._connection()
        with conn.cursor() as cur:
            cur.execute(query)
            value = cur.fetchone()[0]
        return value

    @staticmethod
    def _event_row(event: Mapping[str, Any], run_id: str | None) -> dict[str, Any]:
        meta = event.get("metadata") or {}
        actor_user = ((event.get("actor") or {}).get("user") or {}).get("name")
        src_ip = (event.get("src_endpoint") or {}).get("ip")
        return {
            "uid": meta.get("uid"),
            "time": datetime.fromtimestamp(int(event["time"]) / 1000, tz=timezone.utc),
            "class_uid": event.get("class_uid"),
            "class_name": event.get("class_name"),
            "category_uid": event.get("category_uid"),
            "activity_id": event.get("activity_id"),
            "activity_name": event.get("activity_name"),
            "severity_id": event.get("severity_id"),
            "severity": event.get("severity"),
            "status_id": event.get("status_id"),
            "status": event.get("status"),
            "source_name": meta.get("log_source", "unknown"),
            "actor_user": actor_user,
            "src_ip": src_ip,
            "run_id": run_id,
            "event": Jsonb(dict(event)),
        }
