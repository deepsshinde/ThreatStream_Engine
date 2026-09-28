"""Security findings orchestration (deterministic signals + AI-assisted analysis).

Pipeline:

    normalized events
        -> CorrelationEngine            (deterministic, rule/YAML based)
        -> candidate selection          (correlated, failed, or high-severity events)
        -> MITRERetriever               (RAG context, optional)
        -> LLM chain                    (Ollama if up, deterministic fallback always)
        -> SecurityFinding[]            (Pydantic-validated, storage-shaped)

Every finding records which engine produced it, and findings are keyed by a
deterministic ``finding_id`` so re-analysis is idempotent in storage.
"""

from __future__ import annotations

import hashlib
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from app.ai.analyzer import analyze_with_chains, build_llm_chain
from app.ai.base import AnalysisRequest
from app.ai.ollama_llm import OllamaLLM
from app.config import Settings
from app.mapping.resolver import get_path
from app.processing.correlation import CorrelationEngine, load_rules
from app.rag.context_builder import build_query
from app.rag.retriever import MITRERetriever
from app.schemas.findings import SecurityFinding, SecuritySignal

logger = logging.getLogger("threatstream.analysis")


@dataclass
class AnalysisRunResult:
    signals: list[SecuritySignal] = field(default_factory=list)
    findings: list[SecurityFinding] = field(default_factory=list)
    candidates: int = 0
    engine_used: str | None = None
    llm_errors: int = 0
    retrieval_available: bool = False

    def to_summary(self) -> dict[str, Any]:
        return {
            "signals": len(self.signals),
            "findings": len(self.findings),
            "candidates": self.candidates,
            "engine_used": self.engine_used,
            "llm_errors": self.llm_errors,
            "retrieval_available": self.retrieval_available,
        }


class SecurityAnalyzer:
    """Analyzes normalized events into security findings."""

    def __init__(
        self,
        settings: Settings,
        correlation: CorrelationEngine | None = None,
        retriever: MITRERetriever | None = None,
        ollama: OllamaLLM | None = None,
    ):
        self.settings = settings
        self.correlation = correlation or CorrelationEngine(load_rules(settings.correlation_rules_file))
        self.retriever = retriever if retriever is not None else MITRERetriever(settings.rag)
        self.ollama = ollama if ollama is not None else OllamaLLM(
            settings.ollama.base_url, settings.ollama.model, settings.ollama.timeout_sec
        )
        self.mode = settings.analysis.llm

    # ------------------------------------------------------------------ #
    def _is_candidate(self, uid: str | None, event: Mapping[str, Any], signals_by_uid: dict[str, list[SecuritySignal]]) -> bool:
        if uid is None:
            return False
        if uid in signals_by_uid:
            return True
        if event.get("status_id") == 2:
            return True
        try:
            return int(event.get("severity_id", 1) or 1) >= 3
        except (TypeError, ValueError):
            return False

    def analyze_events(self, events: Iterable[Mapping[str, Any]]) -> AnalysisRunResult:
        events = list(events)
        result = AnalysisRunResult()
        if not events:
            return result

        # ---- 1. deterministic correlation ----
        result.signals = self.correlation.process(events)
        signals_by_uid: dict[str, list[SecuritySignal]] = defaultdict(list)
        for signal in result.signals:
            for uid in signal.event_uids:
                signals_by_uid[uid].append(signal)
        logger.info("Correlation: %d signal(s) from %d events", len(result.signals), len(events))

        # ---- 2. candidate selection ----
        candidates: dict[str, Mapping[str, Any]] = {}
        for event in events:
            uid = get_path(event, "metadata.uid")
            if uid is not None and self._is_candidate(uid, event, signals_by_uid):
                candidates[str(uid)] = event
        limited = dict(list(candidates.items())[: self.settings.analysis.max_candidates])
        result.candidates = len(limited)
        if not limited:
            return result

        # ---- 3. analysis (RAG + LLM chain) ----
        result.retrieval_available = self.retriever.available
        engines = build_llm_chain(self.mode, self.ollama)
        logger.info(
            "Analyzing %d candidate event(s) with engine chain: %s",
            len(limited),
            " -> ".join(e.name for e in engines),
        )
        for uid, event in limited.items():
            event_signals = signals_by_uid.get(uid, [])
            retrieval = None
            if self.retriever is not None:
                retrieval = self.retriever.retrieve(build_query(event, event_signals))
            request = AnalysisRequest(event=event, signals=event_signals, retrieval=retrieval)
            engine_result = analyze_with_chains(request, engines)
            result.engine_used = engine_result.engine
            if engine_result.llm_error:
                result.llm_errors += 1

            primary = max(event_signals, key=lambda s: s.risk_score, default=None)
            seed = f"{uid}|{'|'.join(s.signal_id for s in event_signals)}"
            finding = SecurityFinding(
                finding_id=hashlib.sha256(seed.encode()).hexdigest()[:32],
                event_uid=uid,
                correlation_id=primary.signal_id if primary else None,
                verdict=engine_result.analysis.verdict,
                risk_score=engine_result.analysis.risk_score,
                summary=engine_result.analysis.summary,
                signals=[s.model_dump() for s in event_signals],
                mitre_techniques=engine_result.analysis.techniques,
                recommendations=engine_result.analysis.recommendations,
                llm_used=engine_result.engine != "deterministic",
                analysis_engine=engine_result.engine,
            )
            result.findings.append(finding)

        by_verdict: dict[str, int] = defaultdict(int)
        for f in result.findings:
            by_verdict[f.verdict] += 1
        logger.info("Analysis complete: %d finding(s) %s engine=%s", len(result.findings), dict(by_verdict), result.engine_used)
        return result
