"""LLM orchestration: Ollama when available, deterministic fallback otherwise.

This is the component that keeps the project honest:

* ``engine_used`` is recorded on every finding (``ollama`` | ``deterministic``).
* Ollama parse/validation failures -> recorded, then the fallback answer is
  returned (a finding is never dropped because an LLM misbehaved).
* The deterministic answer is computed FIRST and kept, so a flaky LLM can
  never silently zero-out an analysis.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from app.ai.base import AnalysisRequest, LLMParseError, LLMUnavailable, SecurityLLM
from app.ai.fallback_llm import FallbackLLM
from app.ai.ollama_llm import OllamaLLM
from app.schemas.findings import LLMAnalysis

logger = logging.getLogger("threatstream.ai.analyzer")


@dataclass
class EngineResult:
    analysis: LLMAnalysis
    engine: str
    llm_error: str | None = None


def build_llm_chain(mode: str, ollama: OllamaLLM | None) -> list[SecurityLLM]:
    fallback = FallbackLLM()
    if mode == "fallback":
        return [fallback]
    if mode == "ollama":
        return [ollama, fallback] if ollama else [fallback]
    # auto
    if ollama is not None and ollama.is_available():
        return [ollama, fallback]
    if mode == "auto":
        logger.info("Ollama unavailable - analysis will use the deterministic engine")
    return [fallback]


def analyze_with_chains(request: AnalysisRequest, engines: list[SecurityLLM]) -> EngineResult:
    llm_error: str | None = None
    for engine in engines:
        if engine.name != "deterministic":
            try:
                analysis = engine.analyze(request)
                logger.info("LLM analysis complete (engine=%s verdict=%s risk=%d)", engine.name, analysis.verdict, analysis.risk_score)
                return EngineResult(analysis=analysis, engine=engine.name, llm_error=llm_error)
            except LLMUnavailable as exc:
                llm_error = str(exc)
                logger.warning("LLM engine %s unavailable: %s - falling back to deterministic", engine.name, exc)
            except LLMParseError as exc:
                llm_error = str(exc)
                logger.warning("LLM engine %s produced invalid output: %s - falling back to deterministic", engine.name, exc)
        else:  # deterministic always succeeds
            analysis = engine.analyze(request)
            return EngineResult(analysis=analysis, engine=engine.name, llm_error=llm_error)
    raise AssertionError("engine chain always ends with the deterministic fallback")  # pragma: no cover
