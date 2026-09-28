import json
from unittest.mock import patch

import pytest

from app.ai.analyzer import analyze_with_chains, build_llm_chain
from app.ai.base import AnalysisRequest, LLMParseError, LLMUnavailable
from app.ai.fallback_llm import FallbackLLM
from app.ai.ollama_llm import OllamaLLM
from app.schemas.findings import SecuritySignal, TechniqueReference

BRUTE_SIGNAL = SecuritySignal(
    signal_id="sig-1",
    rule_id="brute-force-then-success",
    severity="High",
    description="Repeated failed logons followed by a successful logon",
    risk_score=75,
    mitre_techniques=[TechniqueReference(id="T1110", name="Brute Force")],
    group_key={"actor.user.name": "bob", "src_endpoint.ip": "203.0.113.50"},
    event_uids=["u1", "u2", "u3", "u4", "u5", "u6"],
    first_seen=0,
    last_seen=1,
)


def failed_login_event():
    return {
        "class_name": "Authentication",
        "activity_name": "Logon",
        "status": "Failure",
        "status_id": 2,
        "severity_id": 2,
        "actor": {"user": {"name": "bob"}},
        "src_endpoint": {"ip": "203.0.113.50"},
        "metadata": {"log_source": "aws_cloudtrail", "uid": "u6"},
    }


class TestFallbackLLM:
    def test_brute_force_signal_yields_malicious(self):
        out = FallbackLLM().analyze(AnalysisRequest(event=failed_login_event(), signals=[BRUTE_SIGNAL]))
        assert out.verdict == "malicious"
        assert out.risk_score >= 70
        assert any(t.id == "T1110" for t in out.techniques)
        assert any("brute-force-then-success" in e for e in out.evidence)
        assert any("MFA" in r for r in out.recommendations)

    def test_plain_failed_login_is_low_risk_without_signals(self):
        out = FallbackLLM().analyze(AnalysisRequest(event=failed_login_event(), signals=[]))
        assert out.verdict == "benign"
        assert out.risk_score < 40

    def test_heuristic_service_account_key(self):
        event = {
            "class_name": "API Activity",
            "activity_name": "Create",
            "status": "Success",
            "status_id": 1,
            "severity_id": 2,
            "api": {"operation": "google.iam.admin.v1.CreateServiceAccountKey"},
            "metadata": {"log_source": "gcp_audit", "uid": "x"},
        }
        out = FallbackLLM().analyze(AnalysisRequest(event=event, signals=[]))
        assert any(t.id == "T1098.001" for t in out.techniques)
        assert out.risk_score >= 40
        assert out.verdict in {"suspicious", "malicious"}

    def test_offensive_user_agent_annotated(self):
        event = failed_login_event() | {"http_request": {"user_agent": "stratus-red-team/1.2.3"}}
        out = FallbackLLM().analyze(AnalysisRequest(event=event, signals=[]))
        assert any("user agent" in e for e in out.evidence)

    def test_is_always_available(self):
        assert FallbackLLM().is_available() is True


class TestOllamaParsing:
    def test_valid_json_response(self):
        raw = json.dumps(
            {
                "verdict": "suspicious",
                "risk_score": 55,
                "summary": "odd",
                "techniques": [{"id": "T1110", "name": "Brute Force"}],
                "evidence": ["status=Failure"],
                "recommendations": ["check it"],
            }
        )
        out = OllamaLLM.parse_response(raw)
        assert out.verdict == "suspicious"
        assert out.risk_score == 55

    def test_markdown_fenced_json(self):
        raw = '```json\n{"verdict": "benign", "risk_score": 10, "summary": "ok"}\n```'
        assert OllamaLLM.parse_response(raw).verdict == "benign"

    def test_garbage_raises_parse_error(self):
        with pytest.raises(LLMParseError):
            OllamaLLM.parse_response("I think this event looks pretty chill honestly")

    def test_schema_violation_raises(self):
        with pytest.raises(LLMParseError):
            OllamaLLM.parse_response('{"verdict": "definitely_evil", "risk_score": 9000, "summary": "x"}')

    def test_bad_technique_id_shape_rejected(self):
        with pytest.raises(LLMParseError):
            OllamaLLM.parse_response(
                '{"verdict": "suspicious", "risk_score": 50, "summary": "x", "techniques": [{"id": "bruteforce", "name": "x"}]}'
            )


class TestOllamaAvailability:
    def test_unreachable_server(self):
        llm = OllamaLLM("http://127.0.0.1:59999", "llama3.2:3b", timeout_sec=1)
        assert llm.is_available() is False
        with pytest.raises(LLMUnavailable):
            llm.analyze(AnalysisRequest(event=failed_login_event()))


class TestAnalyzerChain:
    def test_parse_failure_falls_back_with_error_recorded(self):
        mock_ollama = OllamaLLM("http://127.0.0.1:11434", "m")
        with patch.object(OllamaLLM, "is_available", return_value=True), patch.object(
            OllamaLLM, "analyze", side_effect=LLMParseError("not json at all")
        ):
            result = analyze_with_chains(
                AnalysisRequest(event=failed_login_event(), signals=[BRUTE_SIGNAL]),
                [mock_ollama, FallbackLLM()],
            )
        assert result.engine == "deterministic"
        assert result.llm_error is not None
        assert result.analysis.verdict == "malicious"  # fallback still answers

    def test_chain_uses_ollama_when_working(self):
        expected = FallbackLLM().analyze(AnalysisRequest(event=failed_login_event()))
        mock_ollama = OllamaLLM("http://127.0.0.1:11434", "m")
        with patch.object(OllamaLLM, "is_available", return_value=True), patch.object(
            OllamaLLM, "analyze", return_value=expected
        ):
            result = analyze_with_chains(
                AnalysisRequest(event=failed_login_event()), [mock_ollama, FallbackLLM()]
            )
        assert result.engine == "ollama"

    def test_build_llm_chain_modes(self):
        fallback_chain = build_llm_chain("fallback", None)
        assert [e.name for e in fallback_chain] == ["deterministic"]
        with patch.object(OllamaLLM, "is_available", return_value=False):
            auto_chain = build_llm_chain("auto", OllamaLLM("http://x:1", "m"))
        assert [e.name for e in auto_chain] == ["deterministic"]
