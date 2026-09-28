"""Query and prompt-context construction for the RAG layer.

* :func:`build_query` - turns a normalized event + its deterministic signals
  into a retrieval query (no secrets, no raw payloads, just the *semantic*
  descriptors: what happened, who, outcome, detected signals).
* :func:`build_prompt_context` - formats retrieved techniques into the
  bounded context block the LLM receives. Token budget is enforced by
  truncation - prompts for small local models must stay small.
"""

from __future__ import annotations

import json
from typing import Any, Mapping, Sequence

from app.mapping.resolver import get_path
from app.rag.retriever import RetrievalResult
from app.schemas.findings import SecuritySignal

MAX_DESC_CHARS = 420
MAX_DETECTION_CHARS = 240


def event_subject(event: Mapping[str, Any]) -> str:
    """Short human-readable subject: who did what from where, how it ended."""
    actor = get_path(event, "actor.user.name") or "unknown principal"
    ip = get_path(event, "src_endpoint.ip") or "unknown source"
    activity = event.get("activity_name", "unknown activity")
    cls = event.get("class_name", "event")
    status = event.get("status", "Unknown")
    src = get_path(event, "metadata.log_source") or "unknown source system"
    return f"{activity} ({cls}) by {actor} from {ip} on {src}; outcome: {status}"


def build_query(event: Mapping[str, Any], signals: Sequence[SecuritySignal]) -> str:
    parts = [
        f"Security event: {event_subject(event)}.",
        f"OCSF activity={event.get('activity_name')}, class={event.get('class_name')}, "
        f"severity={event.get('severity')}, status={event.get('status')}.",
    ]
    action = get_path(event, "api.operation") or get_path(event, "action")
    if action:
        parts.append(f"Operation/API action: {action}.")
    if signals:
        parts.append(
            "Deterministic detection signals: "
            + "; ".join(f"{s.rule_id} ({s.description})" for s in signals)
            + "."
        )
    return " ".join(parts)


def build_prompt_context(retrieval: RetrievalResult | None) -> str:
    """The RETRIEVED CONTEXT block injected into the LLM prompt."""
    if retrieval is None or not retrieval.available:
        reason = retrieval.reason if retrieval else "retriever disabled"
        return (
            "RETRIEVED MITRE ATT&CK CONTEXT: unavailable "
            f"({reason}). Analyze using only the event and deterministic signals, "
            "and set techniques from your own knowledge cautiously."
        )
    if not retrieval.retrieved_techniques:
        return (
            "RETRIEVED MITRE ATT&CK CONTEXT: no technique above the similarity "
            "threshold matched this event. It may not correspond to a known "
            "attacker technique; only claim a technique with clear evidence."
        )

    lines = [
        "RETRIEVED MITRE ATT&CK CONTEXT (semantic search results, ranked):",
    ]
    for i, tech in enumerate(retrieval.retrieved_techniques, start=1):
        desc = tech.description[:MAX_DESC_CHARS]
        detection = tech.detection[:MAX_DETECTION_CHARS]
        tactics = ", ".join(tech.tactics) if tech.tactics else "n/a"
        lines.append(f"{i}. {tech.id} {tech.name} (similarity={tech.score:.3f}, tactics={tactics})")
        lines.append(f"   Description: {desc}")
        if detection:
            lines.append(f"   Detection: {detection}")
    return "\n".join(lines)


def compact_event_json(event: Mapping[str, Any], max_chars: int = 1500) -> str:
    """A trimmed JSON view of the event for the prompt (avoids huge payloads)."""
    keep = [
        "class_name", "category_name", "activity_name", "severity", "status",
        "status_detail", "action", "time", "actor", "src_endpoint", "dst_endpoint",
        "api", "cloud", "device", "app", "http_request", "status_code", "logon_type",
    ]
    trimmed: dict[str, Any] = {k: event[k] for k in keep if k in event}
    trimmed["metadata"] = {"log_source": get_path(event, "metadata.log_source")}
    text = json.dumps(trimmed, default=str)
    return text[:max_chars]
