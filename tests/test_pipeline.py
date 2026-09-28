import json

import pytest

from app.processing.pipeline import ThreatStreamPipeline

PARTITION = "year=2026/month=09/day=24"

WINDOWS_EVENT = {
    "EventID": 4624,
    "TimeCreated": "2026-09-24T09:30:00Z",
    "Computer": "WIN-DC01.corp.local",
    "EventData": {"TargetUserName": "asmith", "TargetDomainName": "CORP", "IpAddress": "10.1.2.34", "LogonType": "3"},
}


def test_process_cloudtrail_file_end_to_end(make_settings, project_root):
    pipeline = ThreatStreamPipeline(make_settings())
    summary = pipeline.process_file(project_root / "sample_logs" / "cloudtrail.json")

    assert summary.raw == 10
    assert summary.detected == 10
    assert summary.mapped == 10
    assert summary.valid == 10
    assert summary.invalid == 0
    assert summary.duplicates == 0
    assert summary.stored == 10
    assert summary.per_source["aws_cloudtrail"] == 10
    # 7x ConsoleLogin + 1x AssumeRole -> Authentication; CreateUser -> Account Change
    assert summary.per_class["Authentication"] == 8
    assert summary.per_class["Account Change"] == 1
    assert summary.per_class["API Activity"] == 1  # GetCallerIdentity

    partition = pipeline.settings.output_dir / PARTITION
    auth_file = partition / "authentication.jsonl"
    assert auth_file.is_file()
    lines = [json.loads(l) for l in auth_file.read_text().splitlines() if l.strip()]
    assert len(lines) == 8
    # uid derived from deterministic content fingerprint
    assert all(len(e["metadata"]["uid"]) == 64 for e in lines)
    # uids are unique per event content (the 5 failed logins differ by timestamp)
    assert len({e["metadata"]["uid"] for e in lines}) == 8


def test_rerun_is_idempotent_via_dedup_state(make_settings, project_root):
    settings = make_settings()
    first = ThreatStreamPipeline(settings).process_file(project_root / "sample_logs" / "cloudtrail.json")
    assert first.stored == 10

    # Fresh pipeline instance (like a separate CLI invocation): state persisted
    second = ThreatStreamPipeline(settings).process_file(project_root / "sample_logs" / "cloudtrail.json")
    assert second.raw == 10
    assert second.valid == 10
    assert second.duplicates == 10
    assert second.stored == 0


def test_malformed_json_line_is_recorded_not_fatal(make_settings, tmp_path):
    bad_file = tmp_path / "mixed.jsonl"
    bad_file.write_text(json.dumps(WINDOWS_EVENT) + "\n" + "{not valid json at all\n", encoding="utf-8")

    pipeline = ThreatStreamPipeline(make_settings())
    summary = pipeline.process_file(bad_file)

    assert summary.raw == 2
    assert summary.valid == 1
    assert summary.stored == 1
    assert summary.per_stage_failures["ingestion"] == 1

    errors_file = pipeline.settings.errors_dir / "pipeline_errors.jsonl"
    assert errors_file.is_file()
    errors = [json.loads(l) for l in errors_file.read_text().splitlines() if l.strip()]
    assert len(errors) == 1
    assert errors[0]["stage"] == "ingestion"
    assert "malformed JSON" in errors[0]["error"]


def test_unknown_source_events_are_stored_as_detection_failures(make_settings, tmp_path):
    unknown_file = tmp_path / "unknown.json"
    unknown_file.write_text(json.dumps([{"what": "is", "this": 1}, {"still": "unknown"}]), encoding="utf-8")

    pipeline = ThreatStreamPipeline(make_settings())
    summary = pipeline.process_file(unknown_file)

    assert summary.raw == 2
    assert summary.undetected == 2
    assert summary.stored == 0
    assert summary.per_stage_failures["detection"] == 2


def test_validation_failure_is_stored_separately(make_settings, project_root):
    from app.mapping.mapping_loader import load_mappings

    settings = make_settings()
    pipeline = ThreatStreamPipeline(settings)

    # Sabotage one mapping so validation must fail (bad severity constant)
    configs = load_mappings(settings.mappings_dir)
    configs["windows_security"]["ocsf"]["severity_id"] = 9  # out of range
    from app.detection.source_detector import SourceDetector
    from app.mapping.mapper import EventMapper

    pipeline.detector = SourceDetector(configs)
    pipeline.mapper = EventMapper(configs)

    event = {
        "EventID": 4624,
        "TimeCreated": "2026-09-24T09:31:00Z",
        "Computer": "WIN-DC01.corp.local",
        "EventData": {"TargetUserName": "asmith", "IpAddress": "10.1.2.34"},
    }
    summary = pipeline.process_records([event])
    assert summary.raw == 1
    assert summary.mapped == 1
    assert summary.invalid == 1
    assert summary.stored == 0

    errors_file = settings.errors_dir / "pipeline_errors.jsonl"
    errors = [json.loads(l) for l in errors_file.read_text().splitlines() if l.strip()]
    assert errors[0]["stage"] == "validation"
    assert "severity_id 9 out of range" in errors[0]["error"]


def test_pipeline_degrades_gracefully_when_postgres_unreachable(make_settings):
    """postgres.enabled=true but nothing listening -> file-only mode, no crash."""
    pytest.importorskip("psycopg")
    settings = make_settings(
        postgres={
            "enabled": True,
            "host": "127.0.0.1",
            "port": 59999,  # nothing is listening here
            "dbname": "nodb",
            "user": "nouser",
            "password": "nopass",
            "connect_timeout": 1,
        }
    )
    pipeline = ThreatStreamPipeline(settings)
    assert pipeline.postgres is None  # fell back to file-only mode

    summary = pipeline.process_records([WINDOWS_EVENT])
    assert summary.valid == 1
    assert summary.stored == 1
    assert summary.stored_db is None


def test_summary_render_and_run_persisted(make_settings, project_root):
    settings = make_settings()
    pipeline = ThreatStreamPipeline(settings)
    summary = pipeline.process_file(project_root / "sample_logs" / "windows_security.json")
    text = summary.render()
    assert "PIPELINE SUMMARY" in text
    assert "Valid" in text
    assert "aws_cloudtrail" not in text
    assert "windows_security" in text

    runs_file = settings.runs_dir / "runs.jsonl"
    assert runs_file.is_file()
    run = json.loads(runs_file.read_text().strip().splitlines()[-1])
    assert run["run_id"] == summary.run_id
    assert run["stored"] == summary.stored
