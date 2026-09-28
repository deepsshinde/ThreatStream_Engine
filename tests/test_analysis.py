"""End-to-end findings: pipeline -> analysis -> stored findings (file + quality checks)."""

import pytest

from app.ai.ollama_llm import OllamaLLM
from app.processing.analysis import SecurityAnalyzer
from app.rag.context_builder import build_prompt_context, build_query
from app.rag.retriever import MITRERetriever
from tests.factories import cloudtrail_event


@pytest.fixture
def analyzed_settings(make_settings, project_root):
    return make_settings(
        analysis={"enabled": True, "llm": "fallback", "max_candidates": 100},
        rag={"data_dir": str(project_root / "data" / "mitre"), "top_k": 3, "similarity_threshold": 0.05, "embedder": "hashing"},
    )


class TestFindingsEndToEnd:
    def test_pipeline_produces_findings(self, analyzed_settings, project_root):
        from app.processing.pipeline import ThreatStreamPipeline

        pipeline = ThreatStreamPipeline(analyzed_settings)
        assert pipeline.analyzer is not None
        summary = pipeline.process_file(project_root / "sample_logs" / "cloudtrail.json")

        assert summary.signals is not None and summary.signals >= 2  # attempt + sequence
        assert summary.findings >= 5  # correlated events + failed logins

        findings = list(pipeline.storage.iter_findings())
        assert findings
        malicious = [f for f in findings if f["verdict"] == "malicious"]
        assert malicious, "brute force sequence must produce malicious findings"
        assert all(f["analysis_engine"] == "deterministic" for f in findings)
        assert all(f["llm_used"] is False for f in findings)
        brute_findings = [
            f for f in malicious
            if any(s["rule_id"] == "brute-force-then-success" for s in f["signals"])
        ]
        assert brute_findings, "malicious findings must carry the sequence signal"
        top = brute_findings[0]
        assert top["correlation_id"]
        assert any(t["id"] in {"T1110", "T1078"} for t in top["mitre_techniques"])

    def test_findings_are_idempotent(self, analyzed_settings, project_root):
        from app.processing.pipeline import ThreatStreamPipeline

        pipeline = ThreatStreamPipeline(analyzed_settings)
        pipeline.process_file(project_root / "sample_logs" / "cloudtrail.json")
        ids_first = {f["finding_id"] for f in pipeline.storage.iter_findings()}

        analyzer = SecurityAnalyzer(analyzed_settings)
        events = list(pipeline.storage.iter_stored_events())
        again = analyzer.analyze_events(events)
        ids_again = {f.finding_id for f in again.findings}
        stored_second = pipeline.storage.store_findings([f.to_row() for f in again.findings])
        assert ids_again == ids_first
        assert stored_second == 0


class TestCandidateSelection:
    def test_benign_success_events_are_not_analyzed(self, analyzed_settings):
        analyzer = SecurityAnalyzer(analyzed_settings)
        events = [
            {
                "class_name": "Authentication", "status_id": 1, "severity_id": 1,
                "metadata": {"uid": "benign-1"}, "actor": {"user": {"name": "x"}},
            }
        ]
        result = analyzer.analyze_events(events)
        assert result.candidates == 0
        assert result.findings == []


class TestRagGlue:
    def test_query_and_context_without_index(self, analyzed_settings, tmp_path):
        settings = analyzed_settings
        settings.rag.data_dir = tmp_path / "empty-mitre"  # no index built
        retriever = MITRERetriever(settings.rag)
        assert retriever.available is False
        mapped = failed_event = {
            "class_name": "Authentication", "activity_name": "Logon", "status": "Failure",
            "metadata": {"log_source": "aws_cloudtrail", "uid": "x"},
            "actor": {"user": {"name": "bob"}}, "src_endpoint": {"ip": "1.2.3.4"},
        }
        result = retriever.retrieve(build_query(mapped, []))
        assert result.available is False
        assert "build-mitre-index" in result.reason
        ctx = build_prompt_context(result)
        assert "unavailable" in ctx

    def test_query_and_context_with_builtin_index(self, analyzed_settings, tmp_path):
        from app.mitre.embeddings import HashingVectorBackend
        from app.mitre.loader import load_builtin
        from app.mitre.vector_store import TechniqueVectorStore

        techniques = load_builtin(analyzed_settings.project_root / "data" / "mitre" / "builtin_techniques.json")
        store = TechniqueVectorStore.build(techniques, HashingVectorBackend(), source="test")
        store.save(tmp_path)

        analyzed_settings.rag.data_dir = tmp_path
        retriever = MITRERetriever(analyzed_settings.rag)
        assert retriever.available is True
        query = build_query(
            {
                "class_name": "Authentication", "activity_name": "Logon", "status": "Failure",
                "metadata": {"log_source": "aws_cloudtrail", "uid": "x"},
                "actor": {"user": {"name": "bob"}}, "src_endpoint": {"ip": "203.0.113.50"},
            },
            [],
        )
        results = retriever.retrieve(query)
        assert results.available is True
        assert results.retrieved_techniques  # threshold 0.05 -> matches expected
        ctx = build_prompt_context(results)
        assert "RETRIEVED MITRE ATT&CK CONTEXT" in ctx
        assert results.retrieved_techniques[0].id.startswith("T1")
