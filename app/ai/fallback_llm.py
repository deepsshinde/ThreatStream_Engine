"""Deterministic analysis engine - the honest fallback.

This is NOT an LLM and never pretends to be one. It produces a risk score,
verdict, evidence, techniques and recommendations from *explicit heuristics*
you can read below. Every finding produced by it carries
``analysis_engine="deterministic"``.

Scoring model (documented, unit-tested):
  base   : from event outcome/severity
  signals: max risk_score of fired deterministic rules
  heuristics: pattern rules on the mapped activity/operation/user-agent
Verdicts: >=70 malicious, 40-69 suspicious, else benign.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, NamedTuple

from app.ai.base import AnalysisRequest
from app.mapping.resolver import get_path
from app.rag.context_builder import event_subject
from app.schemas.findings import LLMAnalysis, TechniqueReference

_SEVERITY_RISK = {1: 5, 2: 12, 3: 20, 4: 30, 5: 40, 6: 45}


class HeuristicHit(NamedTuple):
    points: int
    technique: TechniqueReference
    evidence: str
    recommendation: str | None = None


class _Rule(NamedTuple):
    pattern: re.Pattern[str]
    points: int
    technique: tuple[str, str] | None
    evidence: str
    recommendation: str | None = None


# (regex over UPPERCASED activity|operation|action string) -> risk contribution
_OPERATION_RULES: tuple[_Rule, ...] = (
    _Rule(re.compile(r"CREATESERVICEACCOUNTKEY|CREATEACCESSKEY"), 30,
          ("T1098.001", "Additional Cloud Credentials"),
          "API call creates new credentials/keys for an account",
          "Verify who created the key, for which account, and whether it is used anywhere."),
    _Rule(re.compile(r"CREATESERVICEACCOUNT|CREATEUSER|4720|ACCOUNT CREATED|CREATE ACCOUNT"), 20,
          ("T1136.003", "Create Account: Cloud Account"),
          "a new account was created",
          "Confirm the change ticket; investigate the creator's recent activity."),
    _Rule(re.compile(r"SETIAMPOLICY|ROLEASSIGNMENTS/WRITE|ATTACH.*POLICY|PUTUSERPOLICY"), 25,
          ("T1098.003", "Additional Cloud Roles"),
          "privilege-impacting role/policy assignment or policy write",
          "Review the granted role scope and whether the principal should hold it."),
    _Rule(re.compile(r"LISTKEYS|GETPASSWORDDATA|SECRET.*GET"), 25,
          ("T1528", "Steal Application Access Token"),
          "enumeration/read of account keys or secrets",
          "Rotate the affected keys; audit the principal's session."),
    _Rule(re.compile(r"GETCALLERIDENTITY"), 10,
          ("T1087.004", "Account Discovery: Cloud Account"),
          "identity enumeration call (who am I / scoping)",
          "Check the user agent and source IP for reconnaissance tooling."),
    _Rule(re.compile(r"ASSUMEROLE|ASSUMEROLEWITH"), 15,
          ("T1078.004", "Cloud Accounts"),
          "role assumption (cross-account privilege change)",
          "Verify the role trust policy and whether this user normally assumes it."),
    _Rule(re.compile(r"SECURITYRULES/WRITE|AUTHORIZATIONPOLICY|MODIFY.*FIREWALL"), 15,
          ("T1562.001", "Impair Defenses: Disable or Modify Tools"),
          "modification of network security controls",
          "Check whether the rule opens administrative ports to untrusted ranges."),
)

_SUSPICIOUS_AGENT_RE = re.compile(
    r"stratus|scout|pacu|nmap|sqlmap|hydra|metasploit|nikto|masscan|attack|red.?team",
    re.IGNORECASE,
)

_SIGNAL_RECOMMENDATIONS = {
    "brute-force-then-success": [
        "Force password reset for the targeted account and review active sessions/tokens.",
        "Check whether MFA was enforced for the successful logon; if not, enable it.",
        "Block or reputation-check the source IP; review its other targets.",
    ],
    "auth-brute-force-attempt": [
        "Review the source IP and its target account list.",
        "Confirm lockout policy is effective and alerting threshold is tuned.",
    ],
    "network-port-scan": [
        "Investigate the scanning source; if external, block at the perimeter.",
        "Review whether any of the scanned ports are exposed/services hardened.",
    ],
}

_GENERIC_RECOMMENDATIONS = [
    "Review related events for the same actor and source IP in the surrounding time window.",
]


def _score_event_base(event: Mapping[str, Any]) -> tuple[int, list[str], list[str]]:
    score = 0
    evidence: list[str] = []
    recommendations: list[str] = []
    status = event.get("status")
    cls = event.get("class_name")

    if status == "Failure":
        if cls == "Authentication":
            score += 15
            evidence.append("authentication outcome is Failure")
        elif cls == "Network Activity":
            score += 8
            evidence.append("network connection was denied/refused")
        else:
            score += 10
            evidence.append("operation result is Failure")
            recommendations.append("Check whether the failure indicates probing of authorisation boundaries.")
    severity_id = int(event.get("severity_id", 1) or 1)
    score += _SEVERITY_RISK.get(severity_id, 5)
    if severity_id >= 3:
        evidence.append(f"event severity is {event.get('severity')} (severity_id={severity_id})")
    return score, evidence, recommendations


class FallbackLLM:
    name = "deterministic"

    def analyze(self, request: AnalysisRequest) -> LLMAnalysis:
        event = request.event
        score = 0
        evidence: list[str] = []
        recommendations: list[str] = []
        techniques: dict[str, TechniqueReference] = {}

        # 1) base from the event itself
        base, ev0, rec0 = _score_event_base(event)
        score += base
        evidence += ev0
        recommendations += rec0

        # 2) deterministic signals are the strongest risk driver
        if request.signals:
            signal_max = max(s.risk_score for s in request.signals)
            score = max(score, signal_max)
            for signal in request.signals:
                evidence.append(f"deterministic signal: {signal.rule_id} ({len(signal.event_uids)} correlated events, risk={signal.risk_score})")
                for t in signal.mitre_techniques:
                    techniques[t.id] = t
                recommendations += _SIGNAL_RECOMMENDATIONS.get(signal.rule_id, [])

        # 3) heuristic rules on mapped activity/operation
        operation = " ".join(
            str(x or "") for x in (
                get_path(event, "api.operation"),
                event.get("activity_name"),
                event.get("action"),
                get_path(event, "status_detail"),
            )
        ).upper()
        for rule in _OPERATION_RULES:
            if rule.pattern.search(operation):
                score += rule.points
                evidence.append(rule.evidence)
                if rule.technique:
                    techniques[rule.technique[0]] = TechniqueReference(id=rule.technique[0], name=rule.technique[1])
                if rule.recommendation:
                    recommendations.append(rule.recommendation)

        user_agent = get_path(event, "http_request.user_agent")
        if isinstance(user_agent, str) and _SUSPICIOUS_AGENT_RE.search(user_agent):
            score += 20
            evidence.append(f"user agent matches offensive-tooling pattern: {user_agent[:80]}")
            techniques.setdefault("T1087.004", TechniqueReference(id="T1087.004", name="Account Discovery: Cloud Account"))
            recommendations.append("Identify the process/person behind this user agent string.")

        # 4) RAG retrieval can only *annotate*, never drive the score alone
        if request.retrieval and request.retrieval.available:
            for tech in request.retrieval.retrieved_techniques[:2]:
                techniques.setdefault(tech.id, TechniqueReference(id=tech.id, name=tech.name))
                evidence.append(f"retrieval context: {tech.id} {tech.name} (similarity={tech.score:.3f})")

        score = min(score, 100)
        verdict = "malicious" if score >= 70 else "suspicious" if score >= 40 else "benign"

        summary = (
            f"Deterministic analysis: {event_subject(event)}. "
            f"Risk score {score}/100 ({verdict}) "
            + (
                f"driven by signal(s): {', '.join(s.rule_id for s in request.signals)}."
                if request.signals
                else "with no fired correlation signals; based on event outcome and heuristic rules only."
            )
        )

        # dedupe while preserving order
        seen: set[str] = set()
        deduped_recs = [r for r in recommendations if not (r in seen or seen.add(r))]
        if not deduped_recs:
            deduped_recs = _GENERIC_RECOMMENDATIONS
        if verdict == "malicious":
            deduped_recs.insert(0, "Escalate to incident response; treat this as an active incident candidate.")

        return LLMAnalysis(
            verdict=verdict,
            risk_score=score,
            summary=summary,
            techniques=list(techniques.values())[:8],
            evidence=evidence[:12],
            recommendations=deduped_recs[:8],
        )

    def is_available(self) -> bool:  # always available, no external dependency
        return True
