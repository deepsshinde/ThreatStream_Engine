"""ThreatStream Engine command line interface.

    python -m app.cli process-file sample_logs/cloudtrail.json
    python -m app.cli process-dir  sample_logs/
    python -m app.cli init-db
    python -m app.cli stats
    python -m app.cli list-sources
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from pathlib import Path

from app.config import Settings, configure_logging, load_settings
from app.exceptions import ThreatStreamError
from app.processing.pipeline import ThreatStreamPipeline
from app.storage.file_storage import FileStorage

logger = logging.getLogger("threatstream.cli")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="threatstream",
        description="ThreatStream Engine - OCSF security log normalization & analytics",
    )
    parser.add_argument("--config", default=None, help="Path to settings.yml")
    parser.add_argument("--log-level", default=None, help="DEBUG, INFO, WARNING, ...")

    sub = parser.add_subparsers(dest="command", required=True)

    p_file = sub.add_parser("process-file", help="Process a single raw log file")
    p_file.add_argument("path", help="Path to a JSON/JSONL log file")

    p_dir = sub.add_parser("process-dir", help="Process every log file in a directory")
    p_dir.add_argument("directory", help="Directory containing log files")

    sub.add_parser("init-db", help="Apply db/schema.sql to the configured PostgreSQL")
    sub.add_parser("stats", help="Summarize stored normalized events")
    sub.add_parser("list-sources", help="List configured log sources")

    p_mitre = sub.add_parser("build-mitre-index", help="Build the MITRE ATT&CK vector index for RAG")
    p_mitre.add_argument("--source", choices=["auto", "stix", "builtin"], default="auto")
    p_mitre.add_argument("--embedder", choices=["auto", "sentence-transformers", "hashing"], default=None)
    p_mitre.add_argument("--stix-file", default=None, help="Path to a local enterprise-attack.json")

    p_corr = sub.add_parser("correlate", help="Run the correlation engine over stored events")
    p_corr.add_argument("--json", action="store_true", help="Print full signal JSON")

    p_findings = sub.add_parser("findings", help="List recent security findings")
    p_findings.add_argument("--limit", type=int, default=10)
    p_findings.add_argument("--verdict", default=None, help="benign|suspicious|malicious|unknown")

    p_analyze = sub.add_parser("analyze-event", help="Analyze one stored event by its uid")
    p_analyze.add_argument("uid", help="metadata.uid of a stored event")

    p_consumer = sub.add_parser("kafka-consumer", help="Consume raw logs from Kafka through the pipeline")
    p_consumer.add_argument("--max-messages", type=int, default=None)
    p_consumer.add_argument("--continuous", action="store_true", help="Never stop polling (production mode)")

    p_analytics = sub.add_parser("analytics", help="Run Spark analytics over the normalized logs")
    p_analytics.add_argument("--input", default=None, help="Normalized logs root (default: output.dir)")
    p_analytics.add_argument("--output", default="analytics_output", help="Parquet output directory")
    return parser


def _cmd_init_db(settings: Settings) -> int:
    from app.storage.postgres import PostgresStorage

    if not settings.postgres.enabled:
        print(
            "PostgreSQL is disabled (postgres.enabled=false). "
            "Start it with `docker compose up -d postgres` and set POSTGRES_ENABLED=true."
        )
        return 1
    try:
        storage = PostgresStorage(settings.postgres, settings.db_schema_file)
        tables = storage.init_schema()
    except ThreatStreamError as exc:
        print(f"ERROR: could not initialize database: {exc}", file=sys.stderr)
        return 1
    print(f"Schema applied to {settings.postgres.describe}; managed tables:")
    for table in tables:
        print(f"  - {table}")
    storage.close()
    return 0


def _table(title: str, pairs: list[tuple[str, int]]) -> list[str]:
    lines = [f"\n{title}:"] if pairs else []
    lines += [f"  {name:<26} : {count}" for name, count in pairs]
    return lines


def _cmd_build_mitre(settings: Settings, args) -> int:
    from app.mitre.index_builder import build_mitre_index

    try:
        result = build_mitre_index(
            settings, source=args.source, embedder_name=args.embedder, stix_file=args.stix_file
        )
    except ThreatStreamError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    print(
        f"MITRE index built: {result['techniques']} techniques, "
        f"embedder={result['embedder_backend']} dim={result['dim']}, "
        f"source={result['source']} ({result['duration_sec']}s)\n"
        f"-> {result['data_dir']}"
    )
    return 0


def _iter_all_stored_events(settings: Settings):
    storage = FileStorage(settings.output_dir, errors_dir=settings.errors_dir, runs_dir=settings.runs_dir)
    yield from storage.iter_stored_events()


def _cmd_correlate(settings: Settings, args) -> int:
    from app.processing.correlation import CorrelationEngine, load_rules

    engine = CorrelationEngine(load_rules(settings.correlation_rules_file))
    events = list(_iter_all_stored_events(settings))
    signals = engine.process(events)
    print(f"Evaluated {len(events)} stored events with {len(engine.rules)} rules -> {len(signals)} signal(s)")
    if not args.json:
        for s in signals:
            print(
                f"  [{s.severity:<6}] {s.rule_id:<26} risk={s.risk_score:<3} "
                f"group={s.group_key} events={len(s.event_uids)} "
                f"mitre={','.join(t.id for t in s.mitre_techniques)}"
            )
    else:
        for s in signals:
            print(s.model_dump_json())
    return 0


def _cmd_findings(settings: Settings, args) -> int:
    rows = []
    if settings.postgres.enabled:
        from app.storage.postgres import PostgresStorage

        try:
            pg = PostgresStorage(settings.postgres, settings.db_schema_file)
            rows, _ = pg.fetch_findings(limit=args.limit, verdict=args.verdict)
        except ThreatStreamError:
            rows = []
    if not rows:
        storage = FileStorage(settings.output_dir, errors_dir=settings.errors_dir, runs_dir=settings.runs_dir)
        rows = sorted(
            (r for r in storage.iter_findings() if not args.verdict or r.get("verdict") == args.verdict),
            key=lambda r: r.get("risk_score", 0),
            reverse=True,
        )[: args.limit]
    if not rows:
        print("No findings yet. Run the pipeline (analysis.enabled=true) first.")
        return 0
    for row in rows:
        engine = "llm" if row.get("llm_used") else "det"
        print(
            f"  [{row.get('verdict','?'):<10}] risk={row.get('risk_score','?'):<3} engine={engine:<3} "
            f"{row.get('finding_id','')[:16]}  {str(row.get('summary',''))[:110]}"
        )
    return 0


def _cmd_analyze_event(settings: Settings, args) -> int:
    from app.ai.analyzer import analyze_with_chains, build_llm_chain
    from app.ai.base import AnalysisRequest
    from app.ai.ollama_llm import OllamaLLM
    from app.processing.correlation import CorrelationEngine, load_rules
    from app.rag.context_builder import build_query
    from app.rag.retriever import MITRERetriever

    # locate the event: PostgreSQL first, files otherwise
    event = None
    if settings.postgres.enabled:
        from app.storage.postgres import PostgresStorage

        try:
            pg = PostgresStorage(settings.postgres, settings.db_schema_file)
            row = pg.fetch_event(args.uid)
            event = row.get("event") if row else None
        except ThreatStreamError:
            pass
    if event is None:
        for candidate in _iter_all_stored_events(settings):
            if (candidate.get("metadata") or {}).get("uid") == args.uid:
                event = candidate
                break
    if event is None:
        print(f"ERROR: no stored event with uid={args.uid}", file=sys.stderr)
        return 1

    engine = CorrelationEngine(load_rules(settings.correlation_rules_file))
    signals = [s for s in engine.process(_iter_all_stored_events(settings)) if args.uid in s.event_uids]
    retriever = MITRERetriever(settings.rag)
    retrieval = retriever.retrieve(build_query(event, signals)) if retriever else None
    ollama = OllamaLLM(settings.ollama.base_url, settings.ollama.model, settings.ollama.timeout_sec)
    engines = build_llm_chain(settings.analysis.llm, ollama)
    result = analyze_with_chains(AnalysisRequest(event=event, signals=signals, retrieval=retrieval), engines)

    analysis = result.analysis
    print(f"engine            : {result.engine}" + (f" (llm_error: {result.llm_error})" if result.llm_error else ""))
    print(f"verdict / risk    : {analysis.verdict} / {analysis.risk_score}")
    print(f"summary           : {analysis.summary}")
    if signals:
        print("signals           : " + ", ".join(f"{s.rule_id}({s.risk_score})" for s in signals))
    if retrieval and retrieval.available and retrieval.retrieved_techniques:
        print("retrieved (RAG)   : " + ", ".join(f"{t.id} ({t.score:.2f})" for t in retrieval.retrieved_techniques[:3]))
    print("techniques        : " + (", ".join(f"{t.id} {t.name}" for t in analysis.techniques) or "none"))
    print("evidence          :")
    for ev in analysis.evidence[:6]:
        print(f"  - {ev}")
    print("recommendations   :")
    for rec in analysis.recommendations[:6]:
        print(f"  - {rec}")
    return 0


def _cmd_kafka_consumer(settings: Settings, args) -> int:
    from app.exceptions import KafkaUnavailable
    from app.ingestion.kafka_consumer import KafkaLogConsumer

    try:
        pipeline = ThreatStreamPipeline(settings)
        consumer = KafkaLogConsumer(settings, pipeline)
        totals = consumer.run(max_messages=args.max_messages, continuous=args.continuous)
    except KafkaUnavailable as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print(
        f"Kafka consumer done: {totals['messages']} messages in {totals['batches']} batch(es) | "
        f"valid={totals['valid']} invalid={totals['invalid']} dupes={totals['duplicates']} "
        f"stored={totals['stored']} (db: {totals['stored_db']}) findings={totals['findings']}"
    )
    return 0


def _cmd_analytics(settings: Settings, args) -> int:
    from app.spark.analytics import get_spark, run_analytics

    spark = get_spark()
    try:
        report = run_analytics(spark, args.input or settings.output_dir, args.output)
    finally:
        spark.stop()
    for name, meta in report["tables"].items():
        print(f"{name:<22} {meta['rows']:>5} rows  -> {meta['path']}")
    return 0


def _cmd_stats(settings: Settings) -> int:
    # --- file storage (always available) ---
    storage = FileStorage(settings.output_dir, errors_dir=settings.errors_dir, runs_dir=settings.runs_dir)
    per_class: Counter[str] = Counter()
    per_source: Counter[str] = Counter()
    per_severity: Counter[str] = Counter()
    total = 0
    for event in storage.iter_stored_events():
        total += 1
        per_class[str(event.get("class_name", "unknown"))] += 1
        per_source[str((event.get("metadata") or {}).get("log_source", "unknown"))] += 1
        per_severity[str(event.get("severity", "unknown"))] += 1

    print("=" * 52)
    print("THREATSTREAM STORAGE STATS (files)")
    print("=" * 52)
    print(f"Stored normalized events : {total}")
    print(f"Output directory         : {storage.output_dir}")
    for block in (
        _table("By log source", per_source.most_common()),
        _table("By OCSF class", per_class.most_common()),
        _table("By severity", per_severity.most_common()),
    ):
        print("\n".join(block))

    runs_file = settings.runs_dir / "runs.jsonl"
    if runs_file.is_file():
        runs = [json.loads(l) for l in runs_file.read_text(encoding="utf-8").splitlines() if l.strip()]
        if runs:
            print("\nRecent runs (file audit log):")
            for run in runs[-5:]:
                print(
                    f"  {run['run_id']}  raw={run['raw']} valid={run['valid']} "
                    f"dups={run['duplicates']} stored={run['stored']} "
                    f"db={run.get('stored_db')} ({run['duration_sec']}s)"
                )

    errors_file = settings.errors_dir / "pipeline_errors.jsonl"
    error_count = 0
    if errors_file.is_file():
        error_count = sum(1 for l in errors_file.read_text(encoding="utf-8").splitlines() if l.strip())
    if error_count:
        print(f"\nStored pipeline failures: {error_count} ({errors_file})")
    print("=" * 52)

    # --- PostgreSQL (optional) ---
    if not settings.postgres.enabled:
        print("PostgreSQL: disabled (postgres.enabled=false)")
        return 0

    from app.storage.postgres import PostgresStorage

    try:
        pg = PostgresStorage(settings.postgres, settings.db_schema_file)
        if not pg.ping():
            print(f"PostgreSQL: ENABLED but unreachable ({settings.postgres.describe})")
            return 0

        print("THREATSTREAM STORAGE STATS (PostgreSQL)")
        print("=" * 52)
        print(f"normalized_events : {pg.count_events()}")
        print(f"validation_errors : {pg.count_errors()}")
        print(f"security_findings : {pg.count_findings()}")
        print(f"processing_runs   : {pg.count_runs()}")
        for block in (
            _table("By log source", pg.count_by("source_name")),
            _table("By OCSF class", pg.count_by("class_name")),
            _table("By severity", pg.count_by("severity")),
        ):
            print("\n".join(block))
        recent = pg.recent_runs(5)
        if recent:
            print("\nRecent runs (PostgreSQL):")
            for run in recent:
                print(
                    f"  {run['run_id']}  raw={run['raw']} valid={run['valid']} "
                    f"dups={run['duplicates']} stored_db={run['stored_db']} ({run['duration_sec']}s)"
                )
        print("=" * 52)
        pg.close()
    except ThreatStreamError as exc:
        print(f"PostgreSQL: unavailable ({exc})")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        settings = load_settings(args.config)
    except ThreatStreamError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    configure_logging(settings, args.log_level)

    if args.command == "stats":
        return _cmd_stats(settings)
    if args.command == "init-db":
        return _cmd_init_db(settings)
    if args.command == "build-mitre-index":
        return _cmd_build_mitre(settings, args)
    if args.command == "correlate":
        return _cmd_correlate(settings, args)
    if args.command == "findings":
        return _cmd_findings(settings, args)
    if args.command == "analyze-event":
        return _cmd_analyze_event(settings, args)
    if args.command == "kafka-consumer":
        return _cmd_kafka_consumer(settings, args)
    if args.command == "analytics":
        return _cmd_analytics(settings, args)

    try:
        pipeline = ThreatStreamPipeline(settings)
    except ThreatStreamError as exc:
        print(f"ERROR: failed to initialize pipeline: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "list-sources":
            from app.mapping.mapping_loader import load_mappings

            print(f"{'SOURCE':<22}{'PRIORITY':<10}CLASS (default)")
            for name, cfg in load_mappings(settings.mappings_dir).items():
                print(f"{name:<22}{cfg.get('priority', 0):<10}{cfg['ocsf']['class_name']}")
            return 0

        if args.command == "process-file":
            summary = pipeline.process_file(Path(args.path))
        elif args.command == "process-dir":
            summary = pipeline.process_directory(Path(args.directory))
        else:  # pragma: no cover - argparse enforces
            return 2
        print(summary.render())
        return 0
    finally:
        pipeline.close()


if __name__ == "__main__":
    sys.exit(main())
