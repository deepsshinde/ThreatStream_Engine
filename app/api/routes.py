"""API routes: read-only stores + the on-demand /analyze AI endpoint."""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field

router = APIRouter()
logger = logging.getLogger("threatstream.api.routes")


def get_state(request: Request):
    return request.app.state.app_state


class AnalyzeRequestBody(BaseModel):
    event: dict[str, Any] = Field(..., description="Raw vendor log event (any supported source)")


@router.get("/health")
def health(state=Depends(get_state)):
    degraded = state.settings.postgres.enabled and state.postgres is None
    mitre = {"available": False}
    try:
        from app.rag.retriever import MITRERetriever

        r = MITRERetriever(state.settings.rag)
        mitre = {"available": r.available, "reason": r.reason if not r.available else None}
    except Exception:  # noqa: BLE001 - health must never 500
        pass
    return {
        "status": "degraded" if degraded else "ok",
        "postgres": ("enabled" if state.postgres else "disabled" if not state.settings.postgres.enabled else "unreachable"),
        "analysis_enabled": state.settings.analysis.enabled,
        "analysis_mode": state.settings.analysis.llm,
        "mitre_index": mitre,
        "backend": "postgres" if state.postgres else "files",
    }


@router.get("/sources")
def sources(state=Depends(get_state)):
    from app.mapping.mapping_loader import load_mappings

    mappings = load_mappings(state.settings.mappings_dir)
    return [
        {
            "source": m["source_name"],
            "priority": m.get("priority", 0),
            "default_class": (m.get("ocsf") or {}).get("class_name"),
            "description": m.get("description") or "",
            "detection": {
                "required_fields": (m.get("detection") or {}).get("required_fields") or [],
                "field_patterns": (m.get("detection") or {}).get("field_patterns") or {},
            },
        }
        for m in sorted(mappings.values(), key=lambda m: -m.get("priority", 0))
    ]


@router.get("/events")
def events(
    class_name: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    source_name: str | None = None,
    actor_user: str | None = None,
    src_ip: str | None = None,
    uid: str | None = None,
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    state=Depends(get_state),
):
    filters = {
        "class_name": class_name, "severity": severity, "status": status,
        "source_name": source_name, "actor_user": actor_user, "src_ip": src_ip, "uid": uid,
    }
    items, total = state.events(filters, limit=limit, offset=offset)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get("/events/{uid}")
def event_by_uid(uid: str, state=Depends(get_state)):
    row = state.event_by_uid(uid)
    if row is None:
        raise HTTPException(404, f"no event with uid={uid}")
    if "event" in row and isinstance(row["event"], dict):
        return row["event"]
    return row


@router.get("/findings")
def findings(
    verdict: str | None = None,
    min_risk: int | None = Query(None, ge=0, le=100),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    state=Depends(get_state),
):
    items, total = state.findings(limit=limit, offset=offset, verdict=verdict, min_risk=min_risk)
    return {"total": total, "limit": limit, "offset": offset, "items": items}


@router.get("/findings/{finding_id}")
def finding_by_id(finding_id: str, state=Depends(get_state)):
    row = state.finding_by_id(finding_id)
    if row is None:
        raise HTTPException(404, f"no finding with id={finding_id}")
    return row


@router.get("/stats")
def stats(state=Depends(get_state)):
    from app.api.deps import AppState

    return state.stats()


@router.post("/analyze")
def analyze(body: AnalyzeRequestBody, state=Depends(get_state)):
    """On-demand analysis of one raw event. The event is NOT persisted.

    Full path: detect -> map -> (dedup-free) uid -> correlate against stored
    context -> RAG retrieve -> LLM chain -> structured verdict.
    """
    from app.ai.analyzer import analyze_with_chains, build_llm_chain
    from app.ai.base import AnalysisRequest
    from app.ai.ollama_llm import OllamaLLM
    from app.deduplication.deduplicator import Deduplicator
    from app.detection.source_detector import SourceDetector
    from app.mapping.mapper import EventMapper
    from app.mapping.mapping_loader import load_mappings
    from app.processing.correlation import CorrelationEngine, load_rules
    from app.rag.context_builder import build_query
    from app.rag.retriever import MITRERetriever
    from app.validation.validator import OCSFValidator

    settings = state.settings
    mappings = load_mappings(settings.mappings_dir)
    detector = SourceDetector(mappings)
    detection = detector.detect(body.event)
    if detection is None:
        raise HTTPException(422, "source not recognized by any mapping (see /api/v1/sources)")

    mapper = EventMapper(mappings)
    try:
        mapped = mapper.map_event(body.event, detection.source_name)
    except Exception as exc:
        raise HTTPException(422, f"mapping error: {exc}") from exc
    mapped["metadata"]["uid"] = Deduplicator.fingerprint(mapped)

    validator = OCSFValidator()
    result_v = validator.validate(mapped)
    if not result_v.valid:
        raise HTTPException(422, {"mapped_to": detection.source_name, "ocsf_errors": result_v.errors})

    # correlate the candidate against the stored history so sequences spanning
    # previous runs still fire (e.g. this success after stored failures)
    engine = CorrelationEngine(load_rules(settings.correlation_rules_file))
    context = list(state.file.iter_stored_events()) + [mapped]
    uid = mapped["metadata"]["uid"]
    signals = [s for s in engine.process(context) if uid in s.event_uids]

    retriever = MITRERetriever(settings.rag)
    retrieval = retriever.retrieve(build_query(mapped, signals)) if retriever else None
    ollama = OllamaLLM(settings.ollama.base_url, settings.ollama.model, settings.ollama.timeout_sec)
    engines = build_llm_chain(settings.analysis.llm, ollama)
    result = analyze_with_chains(AnalysisRequest(event=mapped, signals=signals, retrieval=retrieval), engines)

    return {
        "source": detection.source_name,
        "ocsf_class": mapped.get("class_name"),
        "engine": result.engine,
        "llm_error": result.llm_error,
        "signals": [s.model_dump() for s in signals],
        "retrieval": {
            "available": retrieval.available if retrieval else False,
            "techniques": [
                {"id": t.id, "name": t.name, "score": t.score}
                for t in (retrieval.retrieved_techniques if retrieval else [])
            ],
        },
        "analysis": result.analysis.model_dump(),
    }
