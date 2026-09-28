"""Controlled prompt template for security event analysis.

Design:

* The LLM receives: normalized OCSF event (trimmed), DETERMINISTIC signals
  (clearly labelled as facts), and retrieved MITRE context (clearly labelled
  as retrieved knowledge, not ground truth).
* It must answer with ONLY JSON matching the LLMAnalysis schema; anything
  else is a parse failure handled by the caller.
* The verdict vocabulary matches the pipeline: benign|suspicious|malicious|unknown.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from app.rag.context_builder import build_prompt_context, compact_event_json

if TYPE_CHECKING:
    from app.ai.base import AnalysisRequest

PROMPT_TEMPLATE = """You are a security analyst reviewing a normalized OCSF security event.

Be conservative: most events are benign operational noise. Only raise risk when
there is concrete evidence THIS event is malicious. Deterministic signals
listed below are FACTS computed by rules; the retrieved MITRE context is
reference material, not proof. Do not invent evidence that is not present.

=== NORMALIZED EVENT (OCSF) ===
{event_json}

=== DETERMINISTIC SECURITY SIGNALS (facts from the rule engine) ===
{signals_block}

=== {mitre_context}

=== TASK ===
Assess the event and respond with ONLY a single JSON object (no markdown, no
commentary) exactly in this shape:
{{
  "verdict": "benign" | "suspicious" | "malicious" | "unknown",
  "risk_score": <integer 0-100>,
  "summary": "<2-3 sentences: what happened, why you scored it this way>",
  "techniques": [{{"id": "Txxxx", "name": "..."}}],
  "evidence": ["<concrete fact from the event/signals>", ...],
  "recommendations": ["<actionable next step for an analyst>", ...]
}}

Rules:
- techniques must only include technique IDs that appear in the retrieved context
  or in the deterministic signals. If none apply, return an empty list.
- evidence must cite actual fields present above (e.g. status=Failure, signal id).
- risk_score guidance: 0-25 benign noise, 26-55 worth a look, 56-75 likely malicious
  activity, 76-100 active compromise.
"""


def build_prompt(request: "AnalysisRequest") -> str:
    if request.signals:
        signals_block = "\n".join(
            f"- [{s.severity}] {s.rule_id}: {s.description} "
            f"(risk={s.risk_score}, events={len(s.event_uids)}, "
            f"group={json.dumps(s.group_key)})"
            for s in request.signals
        )
    else:
        signals_block = "- none (no deterministic rule triggered for this event)"
    return PROMPT_TEMPLATE.format(
        event_json=compact_event_json(request.event),
        signals_block=signals_block,
        mitre_context=build_prompt_context(request.retrieval),
    )
