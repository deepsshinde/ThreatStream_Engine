"""Spark batch analytics over partitioned normalized logs.

Reads the OCSF event lake that the pipeline writes as JSONL
(``../logs/<source>/year=YYYY/.../*.jsonl``), and computes security summary
tables that are written as **Parquet** outputs:

* ``events_by_source``        - volume per log source
* ``events_by_class``         - OCSF class x severity
* ``events_per_hour``         - ingest rate per hour
* ``auth_summary``            - per-account auth health: success/fail counts,
                                failure rate, distinct IPs, **success-after-failures**
* ``top_source_ips``          - most active source endpoints

Each table has a ``read_*`` helper so downstream consumers never guess schemas.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app.exceptions import ThreatStreamError

logger = logging.getLogger("threatstream.spark")


def get_spark(app_name: str = "ThreatStreamAnalytics"):
    """Create a local Spark session. JVM/APPs pick from standard env vars."""
    from pyspark.sql import SparkSession

    return (
        SparkSession.builder.appName(app_name)
        .master("local[*]")
        .config("spark.ui.enabled", "false")
        .config("spark.sql.shuffle.partitions", "8")
        .getOrCreate()
    )


def read_normalized_events(spark, base_dir: str | Path):
    """Load all normalized child JSONL partitions into a DataFrame."""
    from pyspark.sql import functions as F
    from pyspark.sql import types as T

    base = Path(base_dir)
    files = [
        str(p)
        for p in base.glob("**/*.jsonl")
        if not any(part.startswith("_") for part in p.relative_to(base).parts[:-1])
    ]
    if not files:
        raise ThreatStreamError(
            f"no normalized *.jsonl under {base} - run the pipeline first (process-dir)"
        )
    df = spark.read.json(files)
    # project OCSF columns we need and derive convenient+guarded shortcuts
    return df.select(
        "class_name",
        "activity_name",
        "status",
        "severity",
        "time",
        F.col("metadata.log_source").alias("log_source"),
        F.col("metadata.uid").alias("uid"),
        F.col("actor.user.name").alias("user"),
        F.col("src_endpoint.ip").alias("src_ip"),
    ).withColumn("event_ts", F.from_unixtime(F.col("time") / 1000).cast("timestamp"))


def run_analytics(spark, base_dir: str | Path, output_dir: str | Path) -> dict[str, Any]:
    """Compute and persist summary tables. Returns report dict."""
    from pyspark.sql import functions as F

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)
    df = read_normalized_events(spark, base_dir)
    report: dict[str, Any] = {"generated_at": datetime.now(timezone.utc).isoformat(), "tables": {}}

    def emit(name: str, frame):
        path = out / name
        frame.coalesce(1).write.mode("overwrite").parquet(str(path))
        rows = frame.count()
        report["tables"][name] = {"rows": rows, "path": str(path)}
        logger.info("Wrote %-22s %5d rows -> %s", name, rows, path)

    by_source = df.groupBy("log_source").count().orderBy(F.desc("count"))
    emit("events_by_source", by_source)

    by_class = (
        df.groupBy("class_name", "severity").count().orderBy("class_name", F.desc("count"))
    )
    emit("events_by_class", by_class)

    per_hour = (
        df.withColumn("hour", F.date_trunc("hour", F.col("event_ts")))
        .groupBy("hour")
        .count()
        .orderBy("hour")
    )
    emit("events_per_hour", per_hour)

    auth = df.filter(F.col("class_name") == "Authentication")
    auth_summary = (
        auth.groupBy("user")
        .agg(
            F.count("*").alias("total_events"),
            F.sum(F.when(F.col("status") == "Success", 1).otherwise(0)).alias("successes"),
            F.sum(F.when(F.col("status") == "Failure", 1).otherwise(0)).alias("failures"),
            F.countDistinct("src_ip").alias("distinct_src_ips"),
            F.max(F.col("event_ts")).alias("last_event_ts"),
            F.min(F.col("event_ts")).alias("first_event_ts"),
            F.max(F.when(F.col("status") == "Failure", 1).otherwise(0)).alias("seen_failure"),
            F.max(F.when(F.col("status") == "Success", 1).otherwise(0)).alias("seen_success"),
        )
        # success-after-failures heuristic for follow-up attention
        .withColumn(
            "success_after_failures",
            (F.col("seen_failure") == 1) & (F.col("seen_success") == 1) & (F.col("failures") >= 3),
        )
        .withColumn(
            "failure_rate", F.round(F.col("failures") / F.greatest(F.col("total_events"), F.lit(1)), 3)
        )
        .orderBy(F.desc("failures"))
    )
    emit("auth_summary", auth_summary)

    top_ips = df.groupBy("src_ip").count().orderBy(F.desc("count"))
    emit("top_source_ips", top_ips)

    return report


def read_table(spark, name: str, output_dir: str | Path):
    """Load one summary Parquet table back as a DataFrame."""
    return spark.read.parquet(str(Path(output_dir) / name))
