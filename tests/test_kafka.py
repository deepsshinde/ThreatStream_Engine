"""Kafka consumer loop tests with a fake broker (no Docker needed).

The fake mimics the kafka-python poll API; the real consumer construction
path is covered by the unavailable-broker test.
"""

import json

import pytest

from app.config import Settings
from app.exceptions import KafkaUnavailable
from app.ingestion.kafka_consumer import KafkaLogConsumer, build_kafka_consumer
from tests.factories import cloudtrail_event, windows_event


class FakeMessage:
    def __init__(self, value, offset):
        self.value = value
        self.offset = offset
        self.partition = 0
        self.timestamp = 0


class FakeTP:
    def __init__(self, topic, partition=0):
        self.topic = topic
        self.partition = partition


class FakeConsumer:
    """Minimal duck-type of kafka.KafkaConsumer: poll()/commit()/close().

    Serves payloads incrementally in chunks (default: everything in one poll).
    """

    def __init__(self, payloads: list[bytes], chunk_size: int | None = None):
        self.payloads = list(payloads)
        self.chunk_size = chunk_size or len(payloads) or 1
        self.commits = 0
        self.closed = False

    def poll(self, timeout_ms, max_records):
        n = min(self.chunk_size, len(self.payloads))
        if n <= 0:
            return {}
        batch, self.payloads = self.payloads[:n], self.payloads[n:]
        tp = FakeTP("security-logs")
        return {tp: [FakeMessage(v, i) for i, v in enumerate(batch)]}

    def commit(self):
        self.commits += 1

    def close(self):
        self.closed = True


def _pipeline(make_settings):
    from app.processing.pipeline import ThreatStreamPipeline

    settings = make_settings(
        analysis={"enabled": True, "llm": "fallback"},
        kafka={"enabled": True, "bootstrap_servers": "fake:0", "topic": "security-logs", "group_id": "g1"},
    )
    return ThreatStreamPipeline(settings), settings


class TestConsumerLoop:
    def test_happy_path_processes_and_commits(self, make_settings):
        pipeline, settings = _pipeline(make_settings)
        payloads = [
            json.dumps(cloudtrail_event()).encode(),
            json.dumps(windows_event(4625)).encode(),
            json.dumps(cloudtrail_event(event_name="DescribeInstances", eventSource="ec2.amazonaws.com")).encode(),
        ]
        consumer = FakeConsumer(payloads)
        totals = KafkaLogConsumer(settings, pipeline, consumer).run()

        assert totals["messages"] == 3
        assert totals["raw"] == 3
        assert totals["valid"] == 3
        assert totals["stored"] == 3
        assert totals["batches"] == 1
        assert consumer.commits >= 1
        assert consumer.closed is True

    def test_malformed_message_is_error_not_crash(self, make_settings):
        pipeline, settings = _pipeline(make_settings)
        payloads = [b"{not json!!!", json.dumps(windows_event(4624, status=None)).encode()]
        consumer = FakeConsumer(payloads)
        totals = KafkaLogConsumer(settings, pipeline, consumer).run()

        assert totals["messages"] == 2
        assert totals["valid"] == 1
        assert totals["errors"] == 1  # ingestion-stage failure recorded
        assert consumer.commits >= 1

    def test_max_messages_stops_early(self, make_settings):
        pipeline, settings = _pipeline(make_settings)
        payloads = [json.dumps(windows_event(4624, status=None, target_user=f"user{i}")).encode() for i in range(10)]
        consumer = FakeConsumer(payloads, chunk_size=2)
        totals = KafkaLogConsumer(settings, pipeline, consumer).run(max_messages=4)
        assert totals["messages"] == 4  # stops after 2 batches of 2

    def test_duplicate_messages_deduped(self, make_settings):
        pipeline, settings = _pipeline(make_settings)
        same = cloudtrail_event()
        payloads = [json.dumps(same).encode(), json.dumps(same).encode()]
        totals = KafkaLogConsumer(settings, pipeline, FakeConsumer(payloads)).run()
        assert totals["duplicates"] == 1
        assert totals["stored"] == 1


class TestRealConsumerConstruction:
    def test_unavailable_broker_raises_typed_error(self, make_settings):
        pytest.importorskip("kafka")
        # kafka-python raises KafkaTimeoutError ("Unable to bootstrap...") against a
        # dead broker, but only after ~30s of retries; simulate its actual failure.
        from unittest.mock import patch

        from kafka.errors import KafkaTimeoutError

        settings = make_settings(
            kafka={"enabled": True, "bootstrap_servers": "127.0.0.1:59998",
                   "topic": "security-logs", "group_id": "nope"}
        )
        with patch("kafka.KafkaConsumer", side_effect=KafkaTimeoutError("Unable to bootstrap")), \
             pytest.raises(KafkaUnavailable, match="docker compose up -d kafka"):
            build_kafka_consumer(settings)

    def test_missing_dependency_raises_typed_error(self, make_settings):
        import builtins
        from unittest.mock import patch

        settings = make_settings(
            kafka={"enabled": True, "bootstrap_servers": "127.0.0.1:59998",
                   "topic": "security-logs", "group_id": "nope"}
        )
        real_import = builtins.__import__
        def no_kafka(name, *a, **kw):
            if name == "kafka" or name.startswith("kafka."):
                raise ImportError("No module named 'kafka'")
            return real_import(name, *a, **kw)

        with patch.object(builtins, "__import__", side_effect=no_kafka), \
             pytest.raises(KafkaUnavailable, match="kafka-python"):
            build_kafka_consumer(settings)
