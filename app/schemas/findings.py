"""Pydantic models for security signals, LLM output and findings.

Two disciplines are enforced here:

1. **The LLM never writes to storage directly.** It returns JSON matching
   :class:`LLMAnalysis`, validated by Pydantic; parse/validation failures are
   handled gracefully (caller falls back to the deterministic analyzer).
2. **Deterministic signals and AI interpretation are separate fields**, so a
   finding never pretends the LLM "discovered" something a rule did.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field

Verdict = Literal["benign", "suspicious", "malicious", "unknown"]


class TechniqueReference(BaseModel):
    id: str = Field(pattern=r"^T\d{4}(\.\d{3})?$")
    name: str


class LLMAnalysis(BaseModel):
    """Structured output we demand from any LLM engine."""

    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    summary: str
    techniques: list[TechniqueReference] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class SecuritySignal(BaseModel):
    """A deterministic (rule-based) security signal - NO AI involved."""

    signal_id: str
    rule_id: str
    severity: str
    description: str
    risk_score: int = Field(ge=0, le=100)
    mitre_techniques: list[TechniqueReference] = Field(default_factory=list)
    group_key: dict[str, str] = Field(default_factory=dict)
    event_uids: list[str] = Field(default_factory=list)
    first_seen: int = 0
    last_seen: int = 0

    @property
    def correlation_id(self) -> str:
        return self.signal_id


class SecurityFinding(BaseModel):
    """The stored analysis product: deterministic signals + optional LLM view."""

    finding_id: str
    event_uid: str | None = None
    correlation_id: str | None = None
    verdict: Verdict
    risk_score: int = Field(ge=0, le=100)
    summary: str
    signals: list[dict[str, Any]] = Field(default_factory=list)
    mitre_techniques: list[TechniqueReference] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    llm_used: bool = False
    analysis_engine: str = "deterministic"

    def to_row(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "event_uid": self.event_uid,
            "correlation_id": self.correlation_id,
            "verdict": self.verdict,
            "risk_score": self.risk_score,
            "summary": self.summary,
            "signals": self.signals,
            "mitre_techniques": [t.model_dump() for t in self.mitre_techniques],
            "recommendations": self.recommendations,
            "llm_used": self.llm_used,
            # not a DB column (llm_used covers it there); surfaced in file sinks/API
            "analysis_engine": self.analysis_engine,
        }
