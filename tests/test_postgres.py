"""PostgreSQL integration tests.

Skipped automatically when no database is reachable, so CI / laptops without
Docker still run the full unit suite. To run them:

    docker compose up -d postgres
    pytest tests/test_postgres.py

or point THREATSTREAM_TEST_CONNINFO at any reachable cluster.
"""

from __future__ import annotations

import os

import pytest

psycopg = pytest.importorskip("psycopg", reason="psycopg not installed")

pytestmark = pytest.mark.pg_integration

from app.config import PostgresSettings  # noqa: E402
from app.deduplication.deduplicator import Deduplicator  # noqa: E402
from app.mapping.mapper import EventMapper  # noqa: E402
from app.processing.pipeline import ThreatStreamPipeline  # noqa: E402
from app.storage.postgres import TABLES, PostgresStorage  # noqa: E402
from tests.factories import cloudtrail_event, windows_event  # noqa: E402


def _test_pg_settings() -> PostgresSettings:
    conninfo = os.environ.get("THREATSTREAM_TEST_CONNINFO", "").strip()
    base = {"enabled": True, "connect_timeout": 3}
    if conninfo:
        return PostgresSettings(conninfo_override=conninfo, **base)
    return PostgresSettings(
        host=os.environ.get("POSTGRES_HOST", "localhost"),
        port=int(os.environ.get("POSTGRES_PORT", "5432")),
        dbname=os.environ.get("POSTGRES_DB", "threatstream"),
        user=os.environ.get("POSTGRES_USER", "threatstream"),
        password=os.environ.get("POSTGRES_PASSWORD", "threatstream"),
        **base,
    )


PG_SETTINGS = _test_pg_settings()


def _reachable(settings: PostgresSettings) -> bool:
    try:
        conn = psycopg.connect(settings.conninfo, connect_timeout=3)
        conn.close()
        return True
    except Exception:
        return False


PG_AVAILABLE = _reachable(PG_SETTINGS)
pytestmark = pytest.mark.skipif(
    not PG_AVAILABLE,
    reason="PostgreSQL not reachable (docker compose up -d postgres, or set THREATSTREAM_TEST_CONNINFO)",
)


@pytest.fixture
def pg(project_root):
    storage = PostgresStorage(PG_SETTINGS, project_root / "db" / "schema.sql")
    storage.init_schema()
    conn = storage._connection()
    with conn.cursor() as cur:
        for table in ("normalized_events", "validation_errors", "security_findings", "processing_runs"):
            cur.execute(f"TRUNCATE {table} RESTART IDENTITY CASCADE")
    conn.commit()
    yield storage
    storage.close()


@pytest.fixture
def mapped_events(mappings):
    mapper = EventMapper(mappings)
    dedup = Deduplicator()
    raws = [
        (cloudtrail_event(), "aws_cloudtrail"),
        (cloudtrail_event(failed=True), "aws_cloudtrail"),
        (windows_event(4624, status=None), "windows_security"),
    ]
    events = []
    for raw, source in raws:
        ev = mapper.map_event(raw, source)
        ev["metadata"]["uid"] = dedup.fingerprint(ev)
        events.append(ev)
    return events


class TestSchema:
    def test_init_schema_creates_tables_and_is_idempotent(self, pg):
        pg.init_schema()  # second application must not fail
        tables = pg.init_schema()
        assert set(tables) == set(TABLES)
        conn = pg._connection()
        with conn.cursor() as cur:
            cur.execute(
                "SELECT table_name FROM information_schema.tables "
                "WHERE table_schema = 'public' AND table_name = ANY(%s)",
                (list(TABLES),),
            )
            found = {r[0] for r in cur.fetchall()}
        assert found == set(TABLES)


class TestEventStorage:
    def test_insert_is_idempotent_via_uid(self, pg, mapped_events):
        assert pg.store_events(mapped_events, run_id="t1") == 3
        # identical replay inserts nothing (ON CONFLICT uid DO NOTHING)
        assert pg.store_events(mapped_events, run_id="t2") == 0
        assert pg.count_events() == 3

    def test_fetch_event_roundtrip(self, pg, mapped_events):
        pg.store_events(mapped_events)
        uid = mapped_events[0]["metadata"]["uid"]
        row = pg.fetch_event(uid)
        assert row is not None
        assert row["class_name"] == "Authentication"
        assert row["actor_user"] == "bob"
        assert row["src_ip"] == "203.0.113.50"
        assert row["source_name"] == "aws_cloudtrail"
        assert row["event"]["metadata"]["log_source"] == "aws_cloudtrail"
        assert pg.fetch_event("0" * 64) is None

    def test_group_counts(self, pg, mapped_events):
        pg.store_events(mapped_events)
        counts = dict(pg.count_by("source_name"))
        assert counts == {"aws_cloudtrail": 2, "windows_security": 1}
        assert dict(pg.count_by("class_name"))["Authentication"] == 3
        with pytest.raises(ValueError):
            pg.count_by("not_a_column")  # whitelist enforcement


class TestErrorAndRunStorage:
    def test_store_failures(self, pg):
        failures = [
            {"run_id": "r1", "stage": "validation", "error": "Missing required field: class_uid",
             "source_file": "x.json", "source_name": "aws_cloudtrail", "event_preview": "{...}"}
        ]
        assert pg.store_errors(failures) == 1
        assert pg.count_errors() == 1

    def test_store_run_roundtrip(self, pg):
        summary = {
            "run_id": "run-123", "duration_sec": 0.5, "raw": 10, "detected": 10,
            "undetected": 0, "mapped": 10, "valid": 9, "invalid": 1,
            "duplicates": 2, "unique": 7, "stored": 7, "stored_db": 7,
            "per_source": {"aws_cloudtrail": 10}, "per_class": {"Authentication": 9},
            "per_stage_failures": {"validation": 1},
        }
        pg.store_run(summary)
        pg.store_run(summary)  # run_id PK -> idempotent
        assert pg.count_runs() == 1
        recent = pg.recent_runs(1)
        assert recent[0]["run_id"] == "run-123"
        assert recent[0]["stored_db"] == 7


class TestPipelineDualWrite:
    def test_end_to_end_dual_write_and_replay(self, pg, make_settings, project_root):
        settings = make_settings(
            postgres={"enabled": True, "conninfo": PG_SETTINGS.conninfo, "connect_timeout": 3}
        )
        pipeline = ThreatStreamPipeline(settings)
        assert pipeline.postgres is not None

        summary = pipeline.process_file(project_root / "sample_logs" / "cloudtrail.json")
        assert summary.stored == 10          # files
        assert summary.stored_db == 10       # database
        assert pg.count_events() == 10
        pipeline.close()

        # Full replay: dedup skips everything, DB inserts nothing, no duplicates in DB
        replay = ThreatStreamPipeline(settings).process_file(
            project_root / "sample_logs" / "cloudtrail.json"
        )
        assert replay.duplicates == 10
        assert replay.stored_db == 0
        assert pg.count_events() == 10
        assert pg.count_runs() >= 1
