from app.processing.correlation import CorrelationEngine, load_rules
from app.schemas.findings import SecuritySignal

MIN = 60 * 1000  # ms
T0 = 1_790_241_300_000


def auth_event(time_ms, status, user="bob", ip="203.0.113.50", uid=None):
    return {
        "class_name": "Authentication",
        "status": status,
        "time": time_ms,
        "actor": {"user": {"name": user}},
        "src_endpoint": {"ip": ip},
        "metadata": {"uid": uid or f"uid-{user}-{ip}-{time_ms}-{status}"},
    }


def net_event(time_ms, dst_port, ip="203.0.113.77", uid=None):
    return {
        "class_name": "Network Activity",
        "status": "Failure",
        "time": time_ms,
        "src_endpoint": {"ip": ip},
        "dst_endpoint": {"port": dst_port},
        "metadata": {"uid": uid or f"net-{ip}-{dst_port}"},
    }


def _engine(project_root):
    return CorrelationEngine(load_rules(project_root / "config" / "correlation_rules.yml"))


class TestSequenceRule:
    def test_five_failures_then_success_fires(self, project_root):
        engine = _engine(project_root)
        events = [auth_event(T0 + i * MIN, "Failure") for i in range(5)]
        events.append(auth_event(T0 + 5 * MIN, "Success"))
        signals = engine.process(events)
        # the attempt threshold (>=3 failures) fires early, then the sequence fires
        rule_ids = [s.rule_id for s in signals]
        assert rule_ids == ["auth-brute-force-attempt", "brute-force-then-success"]
        sig = signals[1]
        assert isinstance(sig, SecuritySignal)
        assert sig.rule_id == "brute-force-then-success"
        assert sig.severity == "High"
        assert {t.id for t in sig.mitre_techniques} == {"T1110", "T1078"}
        assert sig.group_key == {"actor.user.name": "bob", "src_endpoint.ip": "203.0.113.50"}
        assert len(sig.event_uids) == 6

    def test_four_failures_then_success_fires_attempt_not_sequence(self, project_root):
        engine = _engine(project_root)
        events = [auth_event(T0 + i * MIN, "Failure") for i in range(4)]
        events.append(auth_event(T0 + 4 * MIN, "Success"))
        rule_ids = [s.rule_id for s in engine.process(events)]
        assert rule_ids == ["auth-brute-force-attempt"]  # no 5-failure sequence

    def test_failures_without_success_fire_threshold_rule(self, project_root):
        engine = _engine(project_root)
        events = [auth_event(T0 + i * MIN, "Failure") for i in range(5)]
        signals = engine.process(events)
        assert len(signals) == 1
        assert signals[0].rule_id == "auth-brute-force-attempt"
        assert signals[0].severity == "Medium"

    def test_outside_window_does_not_fire(self, project_root):
        engine = _engine(project_root)
        # failures 6 min apart: never >=3 inside one 10-minute window
        events = [auth_event(T0 + i * 6 * MIN, "Failure") for i in range(5)]
        events.append(auth_event(T0 + 25 * MIN, "Success"))
        assert engine.process(events) == []

    def test_grouping_is_per_user_ip_pair(self, project_root):
        engine = _engine(project_root)
        events = []
        # bob and alice each contribute 2 failures alternating: neither reaches 3 alone
        for i in range(2):
            events.append(auth_event(T0 + i * 30_000, "Failure", user="bob", ip="1.1.1.1"))
            events.append(auth_event(T0 + i * 30_000 + 1000, "Failure", user="alice", ip="1.1.1.2"))
            events.append(auth_event(T0 + i * 30_000 + 2000, "Failure", user="bob", ip="2.2.2.2"))
        assert engine.process(events) == []

    def test_signal_fires_once_per_window(self, project_root):
        engine = _engine(project_root)
        events = [auth_event(T0 + i * MIN, "Failure") for i in range(5)]
        events.append(auth_event(T0 + 5 * MIN, "Success"))
        events.append(auth_event(T0 + 5 * MIN + 1, "Success"))  # re-match, same window
        rule_ids = [s.rule_id for s in engine.process(events)]
        assert rule_ids == ["auth-brute-force-attempt", "brute-force-then-success"]


class TestPortScanRule:
    def test_distinct_ports_fires(self, project_root):
        engine = _engine(project_root)
        events = [net_event(T0 + i * 5_000, port) for i, port in enumerate([22, 23, 25, 110, 143, 445, 3389, 8080])]
        signals = engine.process(events)
        assert len(signals) == 1
        assert signals[0].rule_id == "network-port-scan"
        assert signals[0].group_key == {"src_endpoint.ip": "203.0.113.77"}

    def test_few_ports_does_not_fire(self, project_root):
        engine = _engine(project_root)
        events = [net_event(T0 + i * 5_000, port) for i, port in enumerate([23, 445, 3389])]
        assert engine.process(events) == []

    def test_repeated_same_port_does_not_fire(self, project_root):
        engine = _engine(project_root)
        events = [net_event(T0 + i * 5_000, 22) for i in range(10)]
        assert engine.process(events) == []


class TestRealSampleData:
    def test_cloudtrail_sample_fires_brute_force(self, project_root, make_settings):
        """The end-to-end story: sample logs -> pipeline -> correlation hits."""
        from app.processing.pipeline import ThreatStreamPipeline

        pipeline = ThreatStreamPipeline(make_settings())
        pipeline.process_file(project_root / "sample_logs" / "cloudtrail.json")
        events = list(pipeline.storage.iter_stored_events())

        engine = _engine(project_root)
        signals = engine.process(events)
        assert any(s.rule_id == "brute-force-then-success" for s in signals)

    def test_malformed_rule_file_rejected(self, project_root, tmp_path):
        bad = tmp_path / "rules.yml"
        bad.write_text("rules: [{id: missing-stuff}]", encoding="utf-8")
        import pytest
        from app.exceptions import ConfigError

        with pytest.raises(ConfigError):
            load_rules(bad)
