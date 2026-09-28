"""PySpark analytics tests: real JVM SparkSession over the normalized lake."""

import json

import pytest

pyspark = pytest.importorskip("pyspark")
from pyspark.sql import functions as F

from app.spark.analytics import get_spark, read_normalized_events, run_analytics


@pytest.fixture(scope="session")
def spark():
    spark = get_spark("ThreatStreamTests")
    yield spark
    spark.stop()


def _seed_normalized(tmp_path):
    part = tmp_path / "logs" / "aws_cloudtrail" / "year=2026" / "month=03" / "day=24"
    part.mkdir(parents=True)
    events = []
    for i in range(5):
        events.append(
            {
                "class_name": "Authentication",
                "activity_name": "Logon",
                "status": "Failure" if i < 3 else "Success",
                "severity": "Informational",
                "time": 1_742_750_400_000 + i * 60_000,
                "metadata": {"log_source": "aws_cloudtrail", "uid": f"u{i}"},
                "actor": {"user": {"name": "bob"}},
                "src_endpoint": {"ip": "203.0.113.50"},
            }
        )
    events.append(
        {
            "class_name": "API Activity",
            "status": "Success",
            "severity": "Informational",
            "time": 1_742_750_700_000,
            "metadata": {"log_source": "gcp_audit", "uid": "u9"},
            "actor": {"user": {"name": "alice"}},
            "src_endpoint": {"ip": "198.51.100.23"},
        }
    )
    (part / "events.jsonl").write_text("\n".join(json.dumps(e) for e in events))
    errors = tmp_path / "logs" / "_errors" / "pipeline_errors.jsonl"
    errors.parent.mkdir(parents=True, exist_ok=True)
    errors.write_text('{"stage": "validation", "error": "x"}')
    return tmp_path / "logs"


class TestReadNormalized:
    def test_reads_partitions_and_excludes_underscore_dirs(self, spark, tmp_path):
        base = _seed_normalized(tmp_path)
        df = read_normalized_events(spark, base)
        assert df.count() == 6
        cols = set(df.columns)
        assert {"log_source", "user", "src_ip", "event_ts"} <= cols

    def test_metadata_projection(self, spark, tmp_path):
        base = _seed_normalized(tmp_path)
        df = read_normalized_events(spark, base)
        sources = {r.log_source for r in df.select("log_source").collect()}
        assert sources == {"aws_cloudtrail", "gcp_audit"}


class TestAnalytics:
    def test_run_analytics_writes_parquet_tables(self, spark, tmp_path):
        base = _seed_normalized(tmp_path)
        out = tmp_path / "analytics_output"
        report = run_analytics(spark, base, out)

        assert (tmp_path / "analytics_output" / "events_by_source").exists()
        assert (tmp_path / "analytics_output" / "auth_summary").exists()

        auth = spark.read.parquet(str(out / "auth_summary"))
        rows = {r.user: r.asDict() for r in auth.collect()}
        bob = rows["bob"]
        assert bob["total_events"] == 5
        assert bob["failures"] == 3
        assert bob["successes"] == 2
        assert bob["success_after_failures"] is True
        assert bob["distinct_src_ips"] == 1

        src = spark.read.parquet(str(out / "events_by_source")).collect()
        top = src[0]
        assert top.log_source == "aws_cloudtrail" and top["count"] == 5

        by_class = spark.read.parquet(str(out / "events_by_class")).collect()
        assert {r.class_name for r in by_class} == {"Authentication", "API Activity"}

    def test_report_contents(self, spark, tmp_path):
        base = _seed_normalized(tmp_path)
        report = run_analytics(spark, base, tmp_path / "out2")
        assert set(report["tables"]) == {
            "events_by_source", "events_by_class", "events_per_hour", "auth_summary", "top_source_ips"
        }
        assert report["tables"]["events_by_source"]["rows"] >= 2
