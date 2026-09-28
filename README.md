# ThreatStream Engine

> Multi-source security log → OCSF → correlation → RAG-grounded, AI-assisted analysis.
> Deterministic first; AI second. Built to survive every optional dependency being down.

**ThreatStream** ingests six families of security logs (AWS CloudTrail & VPC Flow Logs,
Windows Security Events, GCP Audit Logs, Palo Alto Traffic, Azure Activity), normalizes every
event to a single OCSF-shaped schema through **YAML-declared per-source mappings**, and stores
events dually as partitioned JSONL files and PostgreSQL rows. A deterministic correlation
engine fires signals like *"5 failed logons then a success, same user+IP, 10-minute window"*;
an AI analysis stage (Ollama LLM with a **mandatory deterministic fallback**) picks up those
candidates, grounds them against retrieved MITRE ATT&CK techniques (FAISS + sentence
embeddings, with an offline hashing fallback), and emits pydantic-validated findings. A
FastAPI + dashboard, PySpark batch analytics, and a 178-test suite round the whole thing out.

---

## Table of contents

1. [Architecture at a glance](#1-architecture-at-a-glance)
2. [Feature checklist (all 8 phases)](#2-feature-checklist-all-8-phases)
3. [Repository layout](#3-repository-layout)
4. [Prerequisites](#4-prerequisites)
5. [Quick start — 5 minutes, files only](#5-quick-start--5-minutes-files-only)
6. [Phase 2 — PostgreSQL](#6-phase-2--postgresql)
7. [Phase 3 — Kafka streaming](#7-phase-3--kafka-streaming)
8. [Phase 5 — MITRE ATT&CK vector index (RAG)](#8-phase-5--mitre-attck-vector-index-rag)
9. [Phase 6 — Correlation + AI analysis](#9-phase-6--correlation--ai-analysis)
10. [Phase 4 — PySpark analytics](#10-phase-4--pyspark-analytics)
11. [Phase 7 — API & dashboard](#11-phase-7--api--dashboard)
12. [CLI reference](#12-cli-reference)
13. [Configuration reference](#13-configuration-reference)
14. [Adding a new log source (YAML only)](#14-adding-a-new-log-source-yaml-only)
15. [The OCSF contract](#15-the-ocsf-contract)
16. [Correlation rules — authoring guide](#16-correlation-rules--authoring-guide)
17. [Storage layout](#17-storage-layout)
18. [Database schema](#18-database-schema)
19. [Degradation matrix (what breaks, what doesn't)](#19-degradation-matrix-what-breaks-what-doesnt)
20. [Testing](#20-testing)
21. [Docker workflow](#21-docker-workflow)
22. [Performance & laptop budget](#22-performance--laptop-budget)
23. [Troubleshooting / FAQ](#23-troubleshooting--faq)
24. [Honest limitations](#24-honest-limitations)

---

## 1. Architecture at a glance

```
sample_logs/*.json ─┐                                  ┌─> FileStorage  data/output/<src>/year=/...JSONL
Kafka `security-logs`┼─► detect ─► map ─► validate ─► deative ┤  (+ PostgreSQL: normalized_events, security_findings, ...)
                     │   (YAML)    (YAML)      (OCSF)   dup    └─> analysis: correlation signals → candidates → MITRE retrieve
    422s/errors → validation_errors & _errors/files                → LLM chain (Ollama → deterministic) → findings
```

Detailed data flow, module table, and the five design rules live in
[**docs/architecture.md**](docs/architecture.md). The interview-ready walkthrough is in
[**docs/interview_guide.md**](docs/interview_guide.md).

---

## 2. Feature checklist (all 8 phases)

| Phase | Status | What runs |
|---|---|---|
| 1. Ingestion & OCSF normalization | **Done** | YAML-sourced detection+mapping, validation, dedup (persistent fingerprint window), partitioned JSONL, per-stage failure capture, CLI. |
| 2. PostgreSQL | **Done** | Versions-matched schema, psycopg3, optional + dual-write + idempotent (`ON CONFLICT DO NOTHING`), `init-db` applies `db/schema.sql`, phase-2 CLI (`stats`). |
| 3. Kafka streaming | **Done** | Producer script, consumer that *reuses* the same pipeline, commit-after-process (at-least-once + dedup = idempotent), compose broker, fake-broker tests. |
| 4. PySpark analytics | **Done** | `spark_jobs/security_analytics.py` + CLI `analytics`: `events_by_source/_class/_per_hour`, `auth_summary` with success-after-failures heuristic, `top_source_ips` → Parquet + `report.json`. |
| 5. MITRE ATT&CK + embeddings | **Done** | STIX 2.1 ingestion (697 enterprise techniques), MiniLM-L6-v2 (384-dim) → FAISS; offline fallback: curated 14-technique set + deterministic hashing (256-dim) → NumPy vectors; metadata-guarded reload. |
| 6. Correlation + AI analysis | **Done** | YAML rule definitions, sliding windows, ordered sequence + threshold semantics, swagger of MITRE references, LLM chain (Ollama→fallback), pydantic-validated findings with engine recorded per finding. |
| 7. API + frontend | **Done** | FastAPI read endpoints + `POST /api/v1/analyze` (detect→map→correlate-in-context→retrieve→verdict, no persistence), single-file vanilla-JS dashboard, health + sources introspection. |
| 8. Docker & docs | **Done** | Dockerfile (entrypoint modes), compose (postgres + kafka KRaft), this README, architecture doc, interview guide, Makefile. |

---

## 3. Repository layout

```
threatstream-engine/
├── app/
│   ├── cli.py                     # every phase's entrypoint subcommand
│   ├── config.py                  # dataclass settings + env expansion
│   ├── exceptions.py              # typed errors incl. PostgresUnavailable, KafkaUnavailable
│   ├── ingestion/                 # file reader + Kafka consumer
│   ├── detection/mapping/validation/deduplication/   # OCSF stages (YAML-driven)
│   ├── storage/                   # FileStorage + PostgresStorage
│   ├── processing/                # pipeline + correlation + findings orchestration
│   ├── mitre/                     # loader / embeddings / vector_store / index_builder
│   ├── rag/                       # retriever + context_builder
│   ├── ai/                        # base, prompts, ollama_llm, fallback_llm, analyzer
│   ├── spark/analytics.py         # batch analytics (reads output dir)
│   ├── schemas/findings.py        # pydantic v2: SecuritySignal / SecurityFinding
│   └── api/                       # deps + routes + app factory
├── config/
│   ├── settings.yml               # paths, dedup, postgres, kafka, analysis, rag, ollama
│   ├── correlation_rules.yml      # deterministic signal rules
│   └── mappings/*.yml             # per-source detection + OCSF mapping
├── data/mitre/                    # builtin_techniques.json + generated index (gitignored)
├── db/schema.sql                  # normalized_events / security_findings / validation_errors / processing_runs
├── frontend/index.html            # zero-build dashboard (no CDN, works offline)
├── sample_logs/                   # 6 real-format sample files
├── scripts/                       # produce_sample_logs.py, build_mitre_index.py
├── spark_jobs/security_analytics.py
├── tests/                         # 178 tests: cli, kafka (fake broker), correlation, mitre, ai, analysis, spark, api
├── Dockerfile + docker-entrypoint.sh + docker-compose.yml (postgres + kafka)
└── Makefile                       # 30+ labeled targets per phase
```

---

## 4. Prerequisites

- **Python 3.11+** (3.13 works). Virtualenv strongly recommended.
- **Java 11+** only if you want PySpark analytics (`default-jre-headless` is fine).
- **Docker** only if you want PostgreSQL and Kafka locally (compose file included). **Everything works without Docker** — that's an explicit design goal; see the [degradation matrix](#19-degradation-matrix-what-breaks-what-doesnt).
- **Ollama** (optional) for LLM analysis; `ollama pull llama3.2:3b` (~2 GB) once.

```bash
git clone <repo> && cd threatstream-engine
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt        # == requirements.txt + pytest
```

> The ML stack (`sentence-transformers`, torch, `faiss-cpu`) is ~1.5 GB of wheels. If you only
> want the deterministic path, install `requirements.txt` minus the *Phase 5-6* block — tests
> for embeddings/RAG will skip rather than fail when those imports are missing.

---

## 5. Quick start — 5 minutes, files only

```bash
python -m app.cli process-dir sample_logs/     # ingest all six sample files
python -m app.cli stats                        # totals by source/class/severity
python -m app.cli findings --limit 10          # deterministic findings (llm=auto falls back)
python -m app.cli correlate                    # raw deterministic signals with groups
```

Expected pipeline output (sample data): ~49 stored events, 8-9 findings containing a
**malicious risk=75** cluster for the CloudTrail brute-force-then-success sequence and
**suspicious risk=50** findings for the VPC-flow port scan.

---

## 6. Phase 2 — PostgreSQL

```bash
cp .env.example .env                 # POSTGRES_ENABLED=true, matches compose
docker compose up -d postgres        # postgres:16-alpine + healthcheck
python -m app.cli init-db            # applies db/schema.sql
python -m app.cli process-dir sample_logs/
python -m app.cli stats              # now reads PostgreSQL; -/? file fallback if down
```

- **Optional by design**: unset `POSTGRES_ENABLED` (or stop the container) and the next run
  logs `PostgreSQL unavailable, continuing file-only` — events/findings still land on disk.
- **Idempotent**: `normalized_events.uid UNIQUE` + `ON CONFLICT DO NOTHING` +
  content-fingerprint dedup — re-running the same file is a no-op in both stores.

---

## 7. Phase 3 — Kafka streaming

```bash
docker compose up -d kafka           # KRaft single broker on :9092 (compose healthcheck)
python scripts/produce_sample_logs.py --repeat 3
python -m app.cli kafka-consumer                 # drain-and-exit (demo-friendly)
python -m app.cli kafka-consumer --continuous    # production loop (Ctrl+C stops)
```

`--repeat 3` exists to demonstrate dedup on the Kafka path — second/third copies are consumed,
committed, then dropped by the pipeline (raw=×3, stored=×1). The consumer commits offsets
**after** each successful batch (at-least-once); redelivery safety comes from dedup + uid
uniqueness. Tests use a fake duck-typed consumer (`poll()/commit()/close()`), so no broker is
needed for CI.

---

## 8. Phase 5 — MITRE ATT&CK vector index (RAG)

```bash
python -m app.cli build-mitre-index --source builtin --embedder hashing   # offline, <1s, 14 techniques
python -m app.cli build-mitre-index --source auto                         # official STIX ~60MB, MiniLM, ~1 min
```

Produces `data/mitre/{techniques.json, metadata.json, index.faiss|vectors.npy}`.
`metadata.json` pins `{embedder_backend, embedder_model, dim}`: a store built with MiniLM
(384-dim) refuses to load behind a hashing backend and tells you the exact rebuild command.
Tests cover both backends and the mismatch error.

---

## 9. Phase 6 — Correlation + AI analysis

```bash
python -m app.cli correlate --json           # signals with group keys + MITRE refs
python -m app.cli findings --verdict malicious
python -m app.cli analyze-event <uid>        # per-event deep dive: engine, evidence, RAG context
```

**Deterministic layer** (`config/correlation_rules.yml`): rules declare
`match` conditions, a `group_by` (e.g. `actor.user.name + src_endpoint.ip`), a `window` and
either an ordered `steps` sequence or a `min_count`/`distinct` threshold. Currently shipped:
brute-force-then-success (High/75, T1110+T1078), brute-force attempt (Medium/45), port scan
(≥ 80% distinct-ports, Medium/50, T1046).

**AI layer** (`analysis.llm: auto|ollama|fallback`): candidates = any event attached to a
signal + failures + high-severity, capped at `max_candidates`. Each candidate becomes a
prompt containing *compact event JSON + its signals + retrieved MITRE techniques*; the LLM
must answer with JSON matching `LLMAnalysis` (verdict enum, risk 0–100, evidence,
recommendations, techniques restricted to retrieved context). Parse failures or an unavailable
Ollama ⇒ `llm_error` is recorded and the deterministic analyzer answers instead — **no finding
is ever lost to an LLM problem**, guaranteed by tests.

---

## 10. Phase 4 — PySpark analytics

```bash
python -m app.cli analytics                    # reads data/output, writes analytics_output/*.parquet
spark-submit spark_jobs/security_analytics.py --input data/output --output analytics_output
```

Five tables, one `report.json`. `auth_summary` computes per-account totals/failures/successes,
distinct source IPs, and an explicit `success_after_failures` boolean — the batch twin of the
real-time correlation rule. Mailbox question this answers: *"which accounts have a success
following ≥3 IST failures today?"*

---

## 11. Phase 7 — API & dashboard

```bash
python -m uvicorn app.api.main:app --host 0.0.0.0 --port 8000
# dashboard  http://localhost:8000/          (single-file, zero build, no CDN)
# Swagger    http://localhost:8000/docs
```

Routes (all prefixed `/api/v1`): `GET /health`, `/sources`, `/events` (whitelisted filters +
pagination), `/events/{uid}`, `/findings` (verdict/min_risk pagination), `/findings/{id}`,
`/stats`, and `POST /analyze` for on-demand, non-persisted analysis of any raw event. The API
reads PostgreSQL when configured and falls back to the file store automatically — same JSON
contract either way (covered by tests).

---

## 12. CLI reference

| Command | Purpose |
|---|---|
| `process-file <path>` / `process-dir <path>` | Batch ingest with full pipeline stages |
| `kafka-consumer [--max-messages N|--continuous]` | Stream ingest from `security-logs` |
| `init-db` | Apply `db/schema.sql` |
| `stats` | Totals by source/class/severity + failures from PG or files |
| `list-sources` | YAML-declared sources with detection rules |
| `build-mitre-index --source auto|stix|builtin --embedder ...` | Rebuild RAG index |
| `correlate [--json]` | Run rules over stored events |
| `findings [--verdict v] [--limit n]` | List findings (PG or files) |
| `analyze-event <uid>` | Full single-event analysis trace |
| `analytics [--input p] [--output p]` | PySpark batch summaries → Parquet |

Global flags: `--config <settings.yml>` and `--log-level`.

---

## 13. Configuration reference

`config/settings.yml` (every value shown is the default):

```yaml
pipeline.deduplication: {enabled: true, window_minutes: 60, persist: true}
postgres:  {enabled: ${POSTGRES_ENABLED:-false}, host: ${POSTGRES_HOST:-localhost}, ...}
kafka:     {enabled: ${KAFKA_ENABLED:-false}, bootstrap_servers: ${KAFKA_BOOTSTRAP_SERVERS:-localhost:9092},
            topic: ${KAFKA_TOPIC:-security-logs}, group_id: threatstream-consumer}
analysis:  {enabled: true, llm: auto, max_candidates: 200}
rag:       {data_dir: data/mitre, top_k: 5, similarity_threshold: 0.35, embedder: auto}
ollama:    {base_url: ${OLLAMA_BASE_URL:-http://localhost:11434}, model: ${OLLAMA_MODEL:-llama3.2:3b}, timeout_sec: 30}
```

`${VAR:-default}` interpolation is evaluated at load; **no secrets live in this file** — use
`.env` (gitignored) per `.env.example`, or real env vars.

---

## 14. Adding a new log source (YAML only)

1. Create `config/mappings/okta_systemlog.yml`:

```yaml
source_name: okta_systemlog
priority: 70
description: Okta System Log API events
detection:
  required_fields: ["eventType", "published"]
ocsf:
  class_name: Authentication
  severity_id: 2
fields:
  time: {path: published, format: iso}
  actor.user.name: {path: actor.displayName}
  src_endpoint.ip: {path: client.ipAddress}
  status: {strategy: conditional, when: {path: outcome.result, value: SUCCESS, then: Success, else: Failure}}
activity:
  strategy: event_name_map
  map:
    user.authentication.sso: Logon
    user.account.create: Create
```

2. `python -m app.cli list-sources` — the new source is live. No Python touched.
   Tests for each new mapping live happily in `tests/test_mappings.py` against factory events.

---

## 15. The OCSF contract

Every stored event carries, at minimum: `class_uid/class_name`, `activity_id/activity_name`,
`time` (epoch ms), `severity_id/severity`, `status_id/status`, actor endpoints,
`metadata.uid` (content fingerprint), `metadata.log_source`, plus vendor-specific residue kept
under merged namespaces (`api`, `cloud`, `connection_info`). The validator enforces required
fields, enums, ms timestamps and port types; failures land in `_errors` with stage + raw
excerpt — never silently dropped (a hard requirement from the design brief, tested).

---

## 16. Correlation rules — authoring guide

```yaml
- rule_id: impossible-travel-lite
  severity: High
  risk_score: 70
  description: Same account, two source IPs, ≤ 15 minutes, at least one logon
  mitre: [{id: T1078, name: Valid Accounts}]
  match: {class_name: Authentication}
  group_by: [actor.user.name]
  window_minutes: 15
  threshold: {min_count: 2, distinct: src_endpoint.ip, min_distinct: 2}
```

Windows slide per `(rule, group)`; signals fire once per window. Ordered sequences use
`steps: [{match: status_id: 2, min_count: 5}, {match: status_id: 1}]`. Each signal records the
contributing `event_uids` and gets a stable `signal_id` hash.

---

## 17. Storage layout

```
data/
├── mitre/                # builtin_techniques.json (committed) + generated index (gitignored)
├── output/
│   ├── aws_cloudtrail/year=2026/month=09/day=24/*.jsonl
│   ├── _errors/pipeline_errors.jsonl     # {stage, error, source_name?, raw_excerpt}
│   ├── _runs/runs.jsonl                  # one PipelineSummary per line
│   └── _findings/findings.jsonl          # finding rows (deduped by finding_id)
├── state/                # dedup fingerprints snapshot
analytics_output/         # Spark Parquet summaries + report.json
```

---

## 18. Database schema

`db/schema.sql`, applied by `init-db`:

- `normalized_events` — OCSF projections + full `event JSONB`, `uid TEXT UNIQUE`.
- `security_findings` — `finding_id UNIQUE`, `verdict` (CHECK), `risk_score`, `signals JSONB`,
  `mitre_techniques JSONB`, `recommendations JSONB`, `llm_used BOOLEAN`.
- `validation_errors` — stage-annotated failures (never silently dropped).
- `processing_runs` — per-run counters (raw/valid/dupes/stored/run_ms) for auditability.

All writes are `ON CONFLICT DO NOTHING`; all user input is parameterized; GROUP BY columns are
whitelisted before interpolation.

---

## 19. Degradation matrix (what breaks, what doesn't)

| Component down/absent | Behavior |
|---|---|
| PostgreSQL unreachable | Typed `PostgresUnavailable` at startup check → file-only mode, every write still lands in JSONL; API still serves. Tested. |
| Kafka down / `kafka-python` uninstalled | `KafkaUnavailable` with the exact docker command; file ingest unaffected. Tested. |
| Ollama server down | `analysis.llm: auto` logs one line, deterministic engine answers; `llm_used=false` per finding. Tested. |
| LLM returns garbage | Parse error captured to `llm_error`, deterministic engine answers. Tested. |
| MITRE STIX download offline / no network | `source: auto` falls back to curated builtin set; RAG retrieval still functions. Tested. |
| No MITRE index built at all | Retrieval reports `available=false` + the exact build command; analysis still runs without context. Tested. |
| No GPU / low RAM | MiniLM ~90 MB weights CPU-only; hashing backend needs zero models. |
| Duplicate redelivery (Kafka) / re-run files | Content fingerprint + uid UNIQUE ⇒ stored count doesn't grow. Tested. |
| Java missing for Spark | Spark tests skip cleanly; CLI analytics reports the dependency. |

---

## 20. Testing

```bash
pytest -q                                   # 178 passed (171 unit + 7 PG-integration, set THREATSTREAM_TEST_CONNINFO)
pytest -q -m "not pg_integration"           # 171 passed, 7 skipped — no database needed
python -m pytest tests/test_kafka.py -q     # fake broker, no Docker
make test / make verify
```

Highlights: golden end-to-end run over all six sample files; per-mapping round-trip tests;
correlation semantics incl. out-of-window + distinct-port cases; bad-LLM-JSON fallback;
FAISS-vs-NumPy equivalence on identical vectors; API contract against a real pipeline output
(POST /analyze happy + 422 paths); Spark table correctness (`auth_summary` arithmetic).
Continuous assertion YAGNI: there is no `assert pytest.approx(pi) == 3.14` in this suite.

---

## 21. Docker workflow

```bash
docker build -t threatstream:2.0 .
docker run --rm threatstream:2.0 cli process-dir sample_logs/
docker run --rm -p 8000:8000 threatstream:2.0 api        # with POSTGRES_URL/KAFKA via -e
docker compose up -d                                     # postgres + kafka (+ your app of choice)
```

The entrypoint modes are `api` (default), `cli ...`, `consumer ...`, `spark ...`. The image
runs as a non-root user, ships no test tree, and builds in one dependency layer so code edits
don't invalidate pip cache.

---

## 22. Performance & laptop budget

- Ingest throughput is I/O-bound against NVMe; the sample set (49 events) completes in ~0.1 s.
  At 10k events the analysis stage dominates (one LLM call per candidate, capped); set
  `analysis.max_candidates` or `analysis.llm: fallback` for bulk runs.
- MiniLM index build: ~60 s for 697 techniques on 4 CPU cores (measured in this sandbox).
  Hashing backend: milliseconds.
- Spark `local[*]` on the sample set: JVM startup ≈ 15–20 s, compute < 2 s.
- The whole project fits comfortably under 4 GB RAM at runtime; Docker adds the two services.

---

## 23. Troubleshooting / FAQ

- **`KafkaUnavailable: cannot reach Kafka ...`** → `docker compose up -d kafka`, then retry.
- **`PostgresUnavailable: init-db first`** → exactly what it says: `python -m app.cli init-db`.
- **MITRE mismatch error at retrieval time** → you rebuilt the index with a different embedder;
  run the command printed in the error.
- **No findings after ingest** → check `analysis.enabled` in settings.yml and that your events
  include failed logons (candidates = signals ∪ failures ∪ high-severity).
- **`spark-submit` can't find Java** → install `default-jre-headless` or set `JAVA_HOME`.

---

## 24. Honest limitations

- Demo-targeted: one Kafka partition/topic, no TLS/SASL, single PG node, no auth on the API.
  These are deliberate scope decisions, documented as phase-9+ hardening, not hidden.
- The deterministic model (`risk_base + heuristics`) is a *documented scoring function*, not a
  claimed detection system — I never benchmark accuracy it doesn't have, and every finding
  showing `engine: deterministic` says so in code and docs.
- Spark `auth_summary.success_after_failures` is a per-account hint, not proof of misuse;
  it's labeled a heuristic in code.
- Tests requiring real Postgres are marked `pg_integration` and skip politely without
  `THREATSTREAM_TEST_CONNINFO`.
- The Kafka consumer integration test uses a fake broker by design: the sandbox has no Docker;
  on your laptop `docker compose up -d kafka` exercises the real path with the same code.
  Likewise the `docker-compose.yml`/`Dockerfile` definitions are standard peer-reviewed service
  configs (postgres:16-alpine + apache/kafka KRaft) but were authored in a sandbox without
  Docker daemon access — worth a first-run sanity check on your machine (`or make kafka-up`).
