"""LLM engine interface + analysis request container."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol, Sequence, runtime_checkable

from app.rag.retriever import RetrievalResult
from app.schemas.findings import LLMAnalysis, SecuritySignal


class LLMUnavailable(Exception):
    """The LLM engine cannot be reached / is not running."""


class LLMParseError(Exception):
    """The LLM answered, but its output failed JSON/Pydantic validation."""


@dataclass
class AnalysisRequest:
    """Everything an LLM engine is allowed to see about one event."""

    event: Mapping[str, Any]
    signals: Sequence[SecuritySignal] = field(default_factory=list)
    retrieval: RetrievalResult | None = None


@runtime_checkable
class SecurityLLM(Protocol):
    """Both OllamaLLM and FallbackLLM implement this; engines are swappable."""

    name: str

    def analyze(self, request: AnalysisRequest) -> LLMAnalysis: ...

    def is_available(self) -> bool: ...
