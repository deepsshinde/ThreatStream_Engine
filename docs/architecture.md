# ThreatStream Engine — Architecture

End-to-end data flow, what each stage actually does, and the failure behaviour that makes
every optional dependency separate from the pipeline's correctness.

```
                 ┌─────────────────────────────────────────────────────────────┐
  files /files/  │  sample_logs/*.json  │  Kafka topic `security-logs`  │     │
                 └───────────┬─────────────────────────────┬─────────────────────┘
                             │   process-file / process-dir│ kafka-consumer
                             ▼                             ▼
                  ┌───────────────────────────────────────────────┐
   STAGE 1 detection    SourceDetector — per-source YAML rules      │
        (config/mappings/*.yml, required_fields + field_patterns)   │
                             │ source_name assigned / undetected -> _errors
                             ▼
                  ┌───────────────────────────────────────────────┐
   STAGE 2 mapping      EventMapper — the same YAML maps vendor     │
                        fields → OCSF-shape (time→epoch ms, fields, │
                        activity strategy, class_name)              │
                             │ mapping error -> _errors
                             ▼
                  ┌───────────────────────────────────────────────┐
   STAGE 3 validation   OCSFValidator — required fields, enums,     │
                        type casts (port /= 'tcp'), timestamp in ms │
                             │ invalid -> _errors (never silently dropped)
                             ▼
                  ┌───────────────────────────────────────────────┐
   STAGE 4 dedup        Deduplicator — fp = SHA-256(content+time),  │
                        seen-set TTL window (persisted to state dir) │
                             │ duplicate -> counted, skipped
                             ▼
                  ┌───────────────────────────────────────────────┐
   STAGE 5a storage     FileStorage (always): JSONL per  YYYY/MM/DD  │
                        files under data/output/<source>/year=/...  │
                  ┌───────────────────────────────────────────────┐
   STAGE 5b dual-write  PostgresStorage (optional, enabled in env): │
                        normalized_events (+ uid UNIQUE),           │
                        security_findings, validation_errors,       │
                        processing_runs — ON CONFLICT DO NOTHING    │
                        | unreachable => PostgresUnavailable,       │
                        | file-only mode, loud warning              │
                             ▼
                  ┌───────────────────────────────────────────────┐
   STAGE 6 analysis     SecurityAnalyzer (analysis.enabled=true):    │
                        correlation (sliding windows per rule+group) │
                        → candidates (any event tied to a signal,    │
                          plus failures/high-severity)               │
                   ┌──── MITRERetriever: FAISS (MiniLM) or          │
                   │     hashing+NumPy fallback, cosine top-k        │
                   │  along src: builtin 14 techniques vs            │
                   │  full STIX bundle (`build-mitre-index --auto`)  │
                   └──── LLM chain: Ollama → deterministic fallback │
                             └► findings → `security_findings` table
                                and data/output/_findings/findings.jsonl
                             ▼
   ____________________________________________________________________________
   │                 READ TIME (never blocks the pipeline)                   │
   │ ┌──────────────────┐  ┌───────────────────┐  ┌───────────────────────┐  │
   │ │ PySpark analytics│  │ FastAPI /api/v1/* │  │ CLI: stats/correlate/ │  │
   │ │ events_by_source │  │ events/findings/  │  │ findings/analyze-event│  │
   │ │ auth_summary ... │  │ stats/analyze +UI │  │ build-mitre-index     │  │
   │ └──────────────────┘  └───────────────────┘  └───────────────────────┘  │
   └──────────────────────────────────────────────────────────────────────────┘
```

Design rules you can defend in review:

1. **YAML-driven everything about sources.** Adding a source is one file in
   `config/mappings/` (detection + OCSF mapping). No Python class per source.
2. **Nothing silently dropped.** Every parseability problem becomes a row in
   `_errors` (file) and `validation_errors` (table) with the stage + raw excerpt.
3. **Deterministic first, AI second.** Correlation and mapping are pure code;
   the LLM chain is additive and *fails loudly into determinism*. Every
   finding stores `analysis_engine` (`ollama`/`deterministic`) and the LLM's
   JSON is pydantic-validated before it can influence a verdict.
4. **Idempotent sinks.** `uid` UNIQUE + `ON CONFLICT DO NOTHING` + content
   fingerprint dedup ⇒ re-running the same input is safe at both layers.
5. **Optional dependencies degrade, never crash.** Postgres down → file
   backend. Ollama down → deterministic engine. MITRE bundle offline → builtin
   14-technique set. kafka-python missing → typed error with the exact
   `docker compose up -d kafka` hint.

Per-module pointers (one file = one responsibility):

| Area | File | Why |
| --- | --- | --- |
| Pipeline orchestrator | `app/processing/pipeline.py` | One code path for batch + stream |
| Correlation engine | `app/processing/correlation.py` + `config/correlation_rules.yml` | Sliding windows, ordered sequences, threshold+distinct |
| Findings orchestrator | `app/processing/analysis.py` | Candidates → RAG context → LLM chain → `SecurityFinding` |
| Findings schema | `app/schemas/findings.py` | pydantic v2, `verdict` Literal, risk 0–100, `to_row()` |
| MITRE load/embed/store | `app/mitre/{loader,embeddings,vector_store,index_builder}.py` | STIX 2.1 parse, MiniLM or hashing, FAISS/NumPy |
| Retrieval + prompt | `app/rag/{retriever,context_builder}.py` | Lazy store, graceful missing-index, budgeted prompt |
| AI chain | `app/ai/{base,prompts,ollama_llm,fallback_llm,analyzer}.py` | Typed errors, JSON-only prompt, parse-fence → pydantic → chain |
| Kafka | `app/ingestion/kafka_consumer.py` | Poll → pipeline per batch → commit-after-success |
| Spark | `app/spark/analytics.py` + `spark_jobs/security_analytics.py` | Summary tables as Parquet + `report.json` |
| API | `app/api/{deps,routes,main}.py` + `frontend/index.html` | Optional-PG accessors, read-only endpoints + POST /analyze |
