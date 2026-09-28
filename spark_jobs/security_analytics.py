#!/usr/bin/env python3
"""Standalone Spark job entrypoint: security summaries over the normalized lake.

Direct run:      python spark_jobs/security_analytics.py --input logs --output analytics_output
spark-submit:    spark-submit spark_jobs/security_analytics.py --input logs --output analytics_output
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.spark.analytics import get_spark, run_analytics


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", default="logs", help="Normalized logs root (JSONL partitions)")
    parser.add_argument("--output", default="analytics_output", help="Where to write Parquet summaries")
    args = parser.parse_args()

    spark = get_spark()
    try:
        report = run_analytics(spark, args.input, args.output)
    finally:
        spark.stop()
    for name, meta in report["tables"].items():
        print(f"{name:<22} {meta['rows']:>5} rows  -> {meta['path']}")
    (Path(args.output) / "report.json").write_text(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
