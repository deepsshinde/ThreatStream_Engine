"""Kafka streaming ingestion.

The consumer implements the same pipeline stages as file ingestion by reusing
:class:`ThreatStreamPipeline` directly - ONE code path for batch and stream.
Delivery semantics:

* offsets are committed **after** successful processing (at-least-once);
* redelivered messages are made harmless by content dedup + the DB
  ``uid`` UNIQUE constraint (idempotent sink).

The consumer object is injected, so the loop is fully testable with a fake
broker (no Docker needed) - the real ``kafka.KafkaConsumer`` is created by
:func:`build_kafka_consumer` only when no consumer is supplied.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any

from app.config import Settings
from app.exceptions import KafkaUnavailable
from app.ingestion.file_reader import RawRecord
from app.processing.pipeline import ThreatStreamPipeline

logger = logging.getLogger("threatstream.kafka")


def build_kafka_consumer(settings: Settings):
    """Create a real KafkaConsumer; raises KafkaUnavailable with clear guidance."""
    try:
        from kafka import KafkaConsumer
        from kafka.errors import KafkaError
    except ImportError as exc:
        raise KafkaUnavailable(
            "kafka-python is not installed (pip install kafka-python)"
        ) from exc

    kafka_cfg = settings.kafka
    try:
        return KafkaConsumer(
            kafka_cfg.topic,
            bootstrap_servers=[s.strip() for s in kafka_cfg.bootstrap_servers.split(",")],
            group_id=kafka_cfg.group_id,
            auto_offset_reset=kafka_cfg.auto_offset_reset,
            enable_auto_commit=False,  # we commit after processing batches
            consumer_timeout_ms=5000,
            request_timeout_ms=15_000,
        )
    except KafkaError as exc:
        # kafka-python 3.x raises KafkaTimeoutError ("Unable to bootstrap...") here
        raise KafkaUnavailable(
            f"cannot reach Kafka at {kafka_cfg.bootstrap_servers} ({exc}). "
            f"Start it with: docker compose up -d kafka"
        ) from exc


class KafkaLogConsumer:
    """Polls a topic and drives the ThreatStream pipeline per batch."""

    def __init__(
        self,
        settings: Settings,
        pipeline: ThreatStreamPipeline,
        consumer: Any | None = None,
        poll_timeout_ms: int = 2000,
        idle_polls_before_stop: int = 3,
    ):
        self.settings = settings
        self.pipeline = pipeline
        self.poll_timeout_ms = poll_timeout_ms
        self.idle_polls_before_stop = idle_polls_before_stop
        self._consumer = consumer if consumer is not None else build_kafka_consumer(settings)

    # ------------------------------------------------------------------ #
    def run(self, max_messages: int | None = None, continuous: bool = False) -> dict[str, int]:
        """Consume until topic drained (idle) or max_messages reached.

        continuous=True keeps polling forever (production mode) until
        interrupted; the default is drain-and-exit (great for demos/tests).
        """
        totals = {"messages": 0, "raw": 0, "valid": 0, "invalid": 0, "duplicates": 0,
                  "stored": 0, "stored_db": 0, "findings": 0, "errors": 0, "batches": 0}
        idle_polls = 0
        topic = self.settings.kafka.topic
        logger.info("Kafka consumer started (topic=%s group=%s)", topic, self.settings.kafka.group_id)
        try:
            while True:
                polled = self._consumer.poll(timeout_ms=self.poll_timeout_ms, max_records=500)
                if not polled:
                    idle_polls += 1
                    if not continuous and idle_polls >= self.idle_polls_before_stop:
                        break
                    if max_messages is not None and totals["messages"] >= max_messages:
                        break
                    continue
                idle_polls = 0

                records: list[RawRecord] = []
                for tp, messages in polled.items():
                    for message in messages:
                        source = f"kafka:{tp.topic}/{tp.partition}@{message.offset}"
                        try:
                            payload = json.loads(message.value.decode("utf-8"))
                            if not isinstance(payload, dict):
                                raise ValueError("message JSON is not an object")
                            records.append(RawRecord(source_file=source, event=payload))
                        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
                            records.append(
                                RawRecord(source_file=source, error=f"malformed Kafka message: {exc}",
                                          raw_text=(message.value[:400] if isinstance(message.value, (bytes, str)) else b"").decode("utf-8", errors="replace") if isinstance(message.value, bytes) else str(message.value)[:400])
                            )

                totals["messages"] += len(records)
                summary = self.pipeline.process_records(records)
                totals["batches"] += 1
                totals["raw"] += summary.raw
                totals["valid"] += summary.valid
                totals["invalid"] += summary.invalid
                totals["duplicates"] += summary.duplicates
                totals["stored"] += summary.stored
                totals["stored_db"] += summary.stored_db or 0
                totals["findings"] += summary.findings or 0
                totals["errors"] += sum(summary.per_stage_failures.values())
                self._consumer.commit()
                logger.info(
                    "Kafka batch: %d messages -> %d stored (run %s) | committed offsets",
                    len(records), summary.stored, summary.run_id,
                )
                if max_messages is not None and totals["messages"] >= max_messages:
                    break
        except KeyboardInterrupt:
            logger.info("Kafka consumer interrupted; committing and shutting down")
        finally:
            try:
                self._consumer.commit()
            except Exception:
                pass
            self._consumer.close()
        logger.info("Kafka consumer stopped: %s", totals)
        return totals
