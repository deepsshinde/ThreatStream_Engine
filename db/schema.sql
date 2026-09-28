-- ============================================================================
-- ThreatStream Engine - PostgreSQL schema (Phase 2)
-- Applied by: app/storage/postgres.py (init_schema) and `python -m app.cli init-db`
-- All statements are idempotent (IF NOT EXISTS), so re-applying is safe.
-- ============================================================================

-- Normalized OCSF events. One row per unique event content (uid = SHA-256
-- fingerprint from the dedup stage, which is also what makes INSERTs
-- idempotent via ON CONFLICT DO NOTHING). Frequently-queried fields are
-- promoted to typed columns; the full OCSF document is kept as JSONB.
CREATE TABLE IF NOT EXISTS normalized_events (
    id              BIGSERIAL PRIMARY KEY,
    uid             TEXT        NOT NULL UNIQUE,
    time            TIMESTAMPTZ NOT NULL,
    class_uid       INTEGER     NOT NULL,
    class_name      TEXT        NOT NULL,
    category_uid    INTEGER     NOT NULL,
    activity_id     INTEGER     NOT NULL,
    activity_name   TEXT,
    severity_id     INTEGER,
    severity        TEXT,
    status_id       INTEGER,
    status          TEXT,
    source_name     TEXT        NOT NULL,
    actor_user      TEXT,
    src_ip          TEXT,
    run_id          TEXT,
    event           JSONB       NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_events_time        ON normalized_events (time DESC);
CREATE INDEX IF NOT EXISTS idx_events_source_time ON normalized_events (source_name, time DESC);
CREATE INDEX IF NOT EXISTS idx_events_class       ON normalized_events (class_name);
CREATE INDEX IF NOT EXISTS idx_events_severity    ON normalized_events (severity_id);
CREATE INDEX IF NOT EXISTS idx_events_actor       ON normalized_events (actor_user);
CREATE INDEX IF NOT EXISTS idx_events_src_ip      ON normalized_events (src_ip);
CREATE INDEX IF NOT EXISTS idx_events_event_gin   ON normalized_events USING GIN (event jsonb_path_ops);

-- Event-level failures from any pipeline stage (called validation_errors per
-- the project spec; the `stage` column covers ingestion/detection/mapping/
-- validation so *every* dropped event is auditable in one place).
CREATE TABLE IF NOT EXISTS validation_errors (
    id              BIGSERIAL PRIMARY KEY,
    run_id          TEXT,
    stage           TEXT        NOT NULL,
    error           TEXT        NOT NULL,
    source_file     TEXT,
    source_name     TEXT,
    event_preview   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_verrors_run   ON validation_errors (run_id);
CREATE INDEX IF NOT EXISTS idx_verrors_stage ON validation_errors (stage);

-- Security findings produced by the correlation/AI analysis layer (Phase 6).
-- The table exists now so the schema evolves explicitly with migrations-style
-- files instead of appearing out of nowhere later.
CREATE TABLE IF NOT EXISTS security_findings (
    id                BIGSERIAL PRIMARY KEY,
    finding_id        TEXT        NOT NULL UNIQUE,
    event_uid         TEXT,
    correlation_id    TEXT,
    verdict           TEXT        NOT NULL,
    risk_score        INTEGER     NOT NULL,
    summary           TEXT        NOT NULL,
    signals           JSONB,
    mitre_techniques  JSONB,
    recommendations   JSONB,
    llm_used          BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_findings_verdict ON security_findings (verdict);
CREATE INDEX IF NOT EXISTS idx_findings_risk    ON security_findings (risk_score DESC);
CREATE INDEX IF NOT EXISTS idx_findings_event   ON security_findings (event_uid);

-- One row per pipeline run - the operational audit trail of the platform.
CREATE TABLE IF NOT EXISTS processing_runs (
    run_id              TEXT PRIMARY KEY,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    duration_sec        REAL,
    raw                 INTEGER,
    detected            INTEGER,
    undetected          INTEGER,
    mapped              INTEGER,
    valid               INTEGER,
    invalid             INTEGER,
    duplicates          INTEGER,
    unique_events       INTEGER,
    stored              INTEGER,
    stored_db           INTEGER,
    per_source          JSONB,
    per_class           JSONB,
    per_stage_failures  JSONB,
    summary             JSONB
);

CREATE INDEX IF NOT EXISTS idx_runs_created ON processing_runs (created_at DESC);
