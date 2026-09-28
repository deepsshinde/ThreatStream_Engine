# ThreatStream — Interview & Walkthrough Guide

Eighteen talking points with the *why* behind each design. Each answer: claim → constraint →
concrete artifact you can point at. Numbers here are from this repo's test run (178 passed).

---

## 1. Why YAML-driven source detection and mapping instead of per-source Python?

**Claim:** adding a log source should be a data problem, not a code problem.
Per-source Python classes invite drift, merge conflicts, and review overhead; they also tempt
engineers to patch per-source logic into shared code paths. Per-source YAML
(`config/mappings/*.yml`) declares detection (`required_fields`, `field_patterns`), mapping
(paths, time parser strategy, activity-name map), and defaults in one reviewable file.
**Proof:** `test_detection.py` + `test_mappings.py` exercise all six sources through the same
generic engine; CLI `list-sources` is generated from the directory, not a registry.

## 2. How do you detect the source of a raw event reliably?

Priority-ordered multi-signal matching: every mapping has `detection.required_fields`
(multi-field keys such as `eventSource`, `eventTime`) and `field_patterns` (`eventSource:
*.amazonaws.com`). Rules are evaluated in `priority` order, so a rule that requires three
specific fields beats a catch-all that requires one. A detection with zero matches becomes a
recorded `_errors` entry, not a silent drop; priority ties are a validation error at load
time, not a runtime surprise.

## 3. Why OCSF as the target schema?

Single question across vendor formats ("show me failed ConsoleLogins from IP X") needs a
single schema. OCSF gives field-level meaning beyond plain JSON (`class_name: Authentication
· activity_name: Logon · status_id: 2`), so the analyzer can compare CloudTrail's
`responseElements.ConsoleLogin == "Failure"` with Windows Event 4625 through OCSF primitives
instead of string tables. It also buys human-readable pivots for free: dashboards can group on
`actor.user.name` whether it came from `userIdentity.userName` or `TargetUserName`.

## 4. How do you keep validation failures visible? (nothing silently dropped)

Every failure object is persisted with its stage (`ingestion|detection|mapping|validation`),
source (when known), error text, and a bounded `raw_excerpt` — to `_errors/pipeline_errors.jsonl`
and the `validation_errors` table. The run summary prints a per-stage failure count *and*
stores paths, so a bad day is measurable from one log line. This is enforced by tests that
seed corrupt messages (Kafka path) and assert the failure artifact exists.

## 5. Why can't two runs double-ingest? (dedup + idempotent sinks)

Two independent layers. First, a **content fingerprint** (SHA-256 over the normalized document
including event time) is kept in a sliding TTL set persisted to `data/state/` between runs —
fast re-runs become no-ops. Second, the sink: `normalized_events.uid UNIQUE` +
`ON CONFLICT DO NOTHING`, and findings dedupe on a deterministic `finding_id` hash of
`(event_uid + signal_ids)`. Kafka's at-least-once make deliberately re-delivered batches
harmless; the demo producer's `--repeat 3` exists precisely to show raw=3× but stored=1×.

## 6. Why not let the dedup "window" be event-time based?

Event time is *user data* — logs can be backfilled, replayed, or arrive hours late (VPC flow
logs routinely do). If accepted-fingerprint memory was keyed to event time, replays would
look new at sensing time and re-enter the lake twice, and growing history would force an
ever-growing window. Instead, the fingerprint **includes event time** while the TTL is
processing/wall time, so replays of *the same content* still hash identically and are caught
regardless of how old they pretend to be. This was a real bug found during Phase 2 and is
documented + guarded in `test_deduplication.py`.

## 7. How does the correlation engine handle ordered sequences vs. thresholds?

Two semantics. An **ordered sequence** (brute force → success) declares `steps`; step N events
must occur *after* the earliest time step N-1 was satisfied, within `window_minutes`, keyed by
`(rule, group)` sliding windows. A **threshold** rule (port scan) declares `min_count` plus an
optional `distinct: field / min_distinct: N`. Every rule also has `group_by`; unmatched group
fields mean the event can't correlate — that's a deliberate, testable choice (a login without
a user is not "same-user brute force"). Fires once per window, and `signal_id` is a stable
hash of rule+group+first_seen so downstream stores stay idempotent.

## 8. Why isn't every event analyzed by the LLM? (candidate selection)

Latency + cost. A 10k-event ingest would need 10k LLM calls per run. Instead the analyzer
takes *evidence-near* candidates — any event attached to a correlation signal, any failure
status, anything severity ≥ 3 — and caps at `analysis.max_candidates` per run (200 default).
On the sample set, that's the six bob-logins and the VPC-flow scan group (~12 events), which is
exactly the interesting subset. The cap is covered by a config test; the selection rule by an
e2e test asserting benign successes are excluded.

## 9. How does RAG become relevant when the LLM has a security corpus anyway?

General LLMs cite ATT&CK fine — when Ollama is even running, and when you trust their
version. Retrieval grounds the answer in *your* curated techniques (or the official 697-
technique STIX bundle), the layer's embedded `detection` hints are verbatim local knowledge,
and `LLMAnalysis.techniques` is *constrained by prompt* to retrieved IDs — so every finding's
MITRE reference traces to retrievable context (visible via `analyze-event <uid>`), not to LLM
memory. It also keeps the deterministic fallback capable of real annotation using the same
retrieval results.

## 10. MITRE STIX vs the builtin subset?

The loader knows three sources: `--source stix <file>` (full enterprise bundle, 697 attack
patterns, STIX 2.1 with revoked/deprecated filtered), `--source builtin` (14 hand-curated
techniques, honest `builtin_techniques.json` shipped in-repo), and `auto`, which takes STIX
when present and builtin otherwise. Demo laptops without network get a working pipeline in
seconds; analysts who want full coverage build once from the official bundle
(`build-mitre-index --source auto`, ~60 s measured in this sandbox).

## 11. What does the MITRE index actually store, and why metadata-guarded?

`data/mitre/`: `techniques.json` (all metadata), `index.faiss` (cosine via L2-normalized
inner product) **or** `vectors.npy` (backend-free NumPy path), and `metadata.json` pinning
`embedder_backend`, `embedder_model`, `dim`, `count`, `source`. Loading with a backend/dim
that doesn't match is a hard error with the rebuild command — otherwise you silently compare
384-dim MiniLM queries against a 256-dim hashed store and get articulate garbage. A test
builds with MiniLM, saves, then loads as hashing and asserts the guard fires.

## 12. Why Ollama prototypes LLM analysis instead of an API provider?

Three of your constraints, respected: **no paid API mandatory**, **reproducible offline**,
**clear separation from deterministic logic**. The Ollama client is stdlib `urllib`
(`/api/tags` for availability, `/api/generate` after a health check with `format=json` + low
temperature), 8-line-of-config all in settings. `auto` mode probes once per run; `ollama` mode
requires it; `fallback` skips it entirely — the mode is config, not code. If you later want a
hosted model, it's a new `SecurityLLM` adapter, not a refactor.

## 13. How is LLM JSON output validated? (`something_nasty("eval")`-proofing)

Three-layer funnel: strip markdown fences → find the first balanced `{...}` → `json.loads` →
a **pydantic v2 schema** (`LLMAnalysis`: `verdict` Literal enum, `risk` 0–100, techniques as
`TechniqueReference` with regex-checked ID shape). Every layer of the funnel has a test (valid,
fenced, garbage, wrong enum, huge risk, malformed technique ID). Parse failure is a typed
`LLMParseError` → chain falls back and records `llm_error` on the finding. The LLM never gets
to bypass validation by phrasing.

## 14. How is deterministic vs AI-assisted kept honest?

*Contract*: every finding carries `analysis_engine ∈ {ollama, deterministic}` and
`llm_used`. The deterministic engine's scoring is a documented, bounded function (status/
severity base + max signal risk + operation regex boosts + suspicious user-agent hints +
retrieval annotation), never claimed as "detection"; the README and code say so. The
correlation layer (which *is* detection) is pure code with its own rule vocabulary, its own
tests, and no LLM in the loop. In the dashboard, findings explicitly show `engine=det/llm` so
a human never confuses a heuristic's opinion with evidence.

## 15. Why at-least-once Kafka consumption + idempotent sink, over exactly-once?

Exactly-once in Kafka means transactions + idempotent consumers coordinated end-to-end —
complexity that doesn't fit a laptop demo and usually still requires an idempotent store.
At-least-once is honest + simple: commit after success, accept redelivery, and let dedup +
`uid UNIQUE` enforce effectively-once observable semantics. A fake-broker test delivers the
same payload twice and asserts commit happened (no crash) and storage stayed deduplicated —
that's the guarantee that matters in practice.

## 16. How do you test streaming and AI without paid services or heavy infra?

**Kafka**: the consumer is written against `poll()/commit()/close()` and a real broker is only
constructed in the factory; tests inject a fake — 4 fast tests cover happy, malformed, early-
stop, and duplicates. **LLM**: `OllamaLLM` and `FallbackLLM` implement the same minimal
interface; parse/availability/fallback paths are unit-tested with mocks; `test_ai.py` runs in
~300 ms. **API**: `TestClient` drives the app against a real pipeline output on a tmpdir. The
suite's 178 tests run in ~75 s with zero external requirements except Java (Spark) and pytest.

## 17. Where do you think the design is weakest / what would you do next?

Three honest items, all enumerated in the README limitations section: (a) the deterministic
fallback's regex boosts cover only what they cover — broadening means writing more rules,
checked against a test harness, so there's no silent confidence inflation; (b) authentication/
authorization on the API and TLS on Kafka are deliberately out of scope for a demo, and that's
called out with explicit next-phase hardening steps; (c) MITRE retrieval quality for
obfuscated phrasing ("exfil outside working hours") depends on the MiniLM embedding — a fine
starting budget, and the index is one command away from the full 697-technique rebuild.

## 18. How would this scale to production?

Concrete phases, all consistent with this codebase: (1) Kafka to multi-broker + schema
registry; `KafkaLogConsumer` already separates loop mechanics from broker construction.
(2) Postgresql partitioning on event date + read replicas; the Pointing-helpers (`query_events`,
`fetch_findings`, `failures_by_source`) are already the shape a repository/service layer takes.
(3) Spark job externalized to EMR/Dataproc with S3/ADLS product-ion paths — the job's
`--input/--output` parameters stand alone. (4) MITRE RAG with kNN index slots (HNSW) and a
rebuild job in CI. (5) Findings lifecycle (ack/assertion states, multi-analyst notes on
JSONB). Nothing in the current design prohibits these; the constraints that *did* prohibit
them are listed as scoping decisions, not afterthoughts.
