"""API tests over the real pipeline output (file backend - no Postgres needed)."""

import pytest
from fastapi.testclient import TestClient

from app.api.deps import AppState
from app.api.main import create_app
from tests.factories import cloudtrail_event


@pytest.fixture
def client(make_settings, project_root):
    settings = make_settings(analysis={"enabled": True, "llm": "fallback"})
    from app.processing.pipeline import ThreatStreamPipeline

    pipeline = ThreatStreamPipeline(settings)
    pipeline.process_file(project_root / "sample_logs" / "cloudtrail.json")
    state = AppState(settings=settings)
    app = create_app(state)
    return TestClient(app)


class TestHealth:
    def test_health_ok_or_degraded_shape(self, client):
        r = client.get("/api/v1/health")
        assert r.status_code == 200
        body = r.json()
        assert body["status"] in {"ok", "degraded"}
        assert body["backend"] in {"postgres", "files"}
        assert body["analysis_mode"] == "fallback"


class TestEvents:
    def test_events_list(self, client):
        r = client.get("/api/v1/events")
        assert r.status_code == 200
        body = r.json()
        assert body["total"] > 0
        assert body["items"][0]["uid"]

    def test_filter_by_status(self, client):
        r = client.get("/api/v1/events", params={"status": "Failure"})
        assert r.status_code == 200
        assert all(i["status"] == "Failure" for i in r.json()["items"])

    def test_filter_by_source(self, client):
        r = client.get("/api/v1/events", params={"source_name": "aws_cloudtrail"})
        assert r.json()["total"] > 0

    def test_event_by_uid(self, client):
        uid = client.get("/api/v1/events").json()["items"][0]["uid"]
        r = client.get(f"/api/v1/events/{uid}")
        assert r.status_code == 200
        assert r.json()["metadata"]["uid"] == uid

    def test_event_not_found(self, client):
        assert client.get("/api/v1/events/does-not-exist").status_code == 404


class TestFindings:
    def test_findings_list(self, client):
        r = client.get("/api/v1/findings")
        assert r.status_code == 200
        items = r.json()["items"]
        assert items
        assert items[0]["risk_score"] >= items[-1]["risk_score"]

    def test_findings_malicious_filter(self, client):
        r = client.get("/api/v1/findings", params={"verdict": "malicious"})
        assert r.status_code == 200
        assert all(i["verdict"] == "malicious" for i in r.json()["items"])

    def test_finding_by_id(self, client):
        fid = client.get("/api/v1/findings").json()["items"][0]["finding_id"]
        r = client.get(f"/api/v1/findings/{fid}")
        assert r.status_code == 200
        assert r.json()["finding_id"] == fid


class TestStatsAndSources:
    def test_stats(self, client):
        r = client.get("/api/v1/stats").json()
        assert r["totals"]["events"] > 0
        assert r["findings"]["total"] > 0
        assert any(b["key"] == "aws_cloudtrail" for b in r["by_source"])

    def test_sources(self, client):
        from app.mapping.mapping_loader import load_mappings

        expected = {m["source_name"] for m in load_mappings("config/mappings").values()}
        r = client.get("/api/v1/sources")
        names = {s["source"] for s in r.json()}
        assert names == expected
        for row in r.json():
            assert row["detection"]["required_fields"], f"{row['source']} must expose its detection rule"

    def test_sources_include_cloudtrail_and_windows(self, client):
        names = {s["source"] for s in client.get("/api/v1/sources").json()}
        assert {"aws_cloudtrail", "windows_security", "gcp_audit", "aws_vpc_flowlogs", "paloalto_firewall"} < names


class TestAnalyze:
    def test_analyze_cloudtrail_failure(self, client):
        payload = cloudtrail_event()  # ConsoleLogin Failure, offensive user-agent
        r = client.post("/api/v1/analyze", json={"event": payload})
        assert r.status_code == 200
        body = r.json()
        assert body["source"] == "aws_cloudtrail"
        assert body["ocsf_class"] == "Authentication"
        assert body["engine"] in {"deterministic", "ollama"}
        assert body["analysis"]["verdict"] in {"benign", "suspicious", "malicious", "unknown"}
        assert body["analysis"]["risk_score"] in range(0, 101)

    def test_analyze_unknown_source_422(self, client):
        r = client.post("/api/v1/analyze", json={"event": {"mystery": True}})
        assert r.status_code == 422

    def test_analyze_invalid_mapped_event_422(self, client):
        bad = cloudtrail_event()
        bad["eventTime"] = "not-a-timestamp"  # detects -> mapping fails (unparseable time)
        r = client.post("/api/v1/analyze", json={"event": bad})
        assert r.status_code == 422
        assert "mapping error" in str(r.json()) or "ocsf_errors" in str(r.json())


class TestDashboard:
    def test_root_serves_dashboard(self, client):
        r = client.get("/")
        assert r.status_code == 200
        assert "ThreatStream" in r.text
