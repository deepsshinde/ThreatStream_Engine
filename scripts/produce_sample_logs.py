#!/usr/bin/env python3
"""Publish the sample logs to the Kafka topic (streaming demo).

    python scripts/produce_sample_logs.py                 # one message per event
    python scripts/produce_sample_logs.py --repeat 3      # replay N times (dedup demo)
    python scripts/produce_sample_logs.py --dir sample_logs/

Requires: docker compose up -d kafka    (topic is auto-created by default)
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app.config import configure_logging, load_settings
from app.ingestion.file_reader import iter_directory_events


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dir", default="sample_logs", help="Directory with raw log files")
    parser.add_argument("--repeat", type=int, default=1, help="Send the dataset N times")
    parser.add_argument("--interval-ms", type=int, default=0, help="Pause between messages")
    parser.add_argument("--config", default=None)
    args = parser.parse_args()

    settings = load_settings(args.config)
    configure_logging(settings)

    from app.exceptions import KafkaUnavailable

    try:
        from kafka import KafkaProducer
        from kafka.errors import NoBrokersAvailable
    except ImportError:
        print("ERROR: kafka-python not installed (pip install kafka-python)", file=sys.stderr)
        return 1

    try:
        producer = KafkaProducer(
            bootstrap_servers=[s.strip() for s in settings.kafka.bootstrap_servers.split(",")],
            value_serializer=lambda v: json.dumps(v).encode("utf-8"),
            key_serializer=lambda v: v.encode("utf-8") if v else None,
            acks="all",
        )
    except NoBrokersAvailable as exc:
        raise SystemExit(f"ERROR: cannot reach Kafka at {settings.kafka.bootstrap_servers} ({exc}). Start it: docker compose up -d kafka")

    events = [r.event for r in iter_directory_events(args.dir) if r.event]
    if not events:
        print(f"ERROR: no events found in {args.dir}", file=sys.stderr)
        return 1

    sent = 0
    topic = settings.kafka.topic
    for round_no in range(args.repeat):
        for event in events:
            key = str((event.get("eventSource") or event.get("EventID") or event.get("service")) or "unknown")[:32]
            producer.send(topic, value=event, key=key)
            sent += 1
            if args.interval_ms:
                time.sleep(args.interval_ms / 1000)
        producer.flush()
        print(f"round {round_no + 1}/{args.repeat}: flushed ({sent} messages sent so far to '{topic}')")
    producer.close()
    print(f"Done: {sent} messages -> topic '{topic}' at {settings.kafka.bootstrap_servers}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
