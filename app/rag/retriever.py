"""MITRE ATT&CK retrieval for security events.

Flow:

    normalized event + deterministic signals
        -> query string (context_builder.build_query)
        -> embedding backend
        -> vector store top-K with similarity threshold
        -> RetrievalResult (techniques + scores + availability info)

If the index has not been built, retrieval degrades to *empty results with a
reason* - never a crash (spec: handle FAISS index missing gracefully).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Sequence

from app.config import RagSettings
from app.mitre.vector_store import TechniqueVectorStore

logger = logging.getLogger("threatstream.rag")


@dataclass
class RetrievedTechnique:
    id: str
    name: str
    score: float
    tactics: list[str] = field(default_factory=list)
    description: str = ""
    detection: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "score": round(self.score, 4),
            "tactics": self.tactics,
            "description": self.description,
            "detection": self.detection,
        }


@dataclass
class RetrievalResult:
    available: bool
    query: str
    retrieved_techniques: list[RetrievedTechnique] = field(default_factory=list)
    reason: str | None = None
    embedder_backend: str | None = None

    @property
    def top_score(self) -> float:
        return max((t.score for t in self.retrieved_techniques), default=0.0)

    def to_dict(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "query": self.query,
            "reason": self.reason,
            "embedder_backend": self.embedder_backend,
            "retrieved_techniques": [t.to_dict() for t in self.retrieved_techniques],
        }


class MITRERetriever:
    """Retrieves relevant MITRE ATT&CK techniques for a security event."""

    def __init__(self, settings: RagSettings):
        self.settings = settings
        self._store: TechniqueVectorStore | None = None
        self._load_error: str | None = None

    @property
    def available(self) -> bool:
        self._ensure_store()
        return self._store is not None

    def _ensure_store(self) -> None:
        if self._store is not None or self._load_error is not None:
            return
        data_dir = Path(self.settings.data_dir)
        if not TechniqueVectorStore.is_available(data_dir):
            self._load_error = (
                f"MITRE index not found in {data_dir} (run: python -m app.cli build-mitre-index)"
            )
            logger.warning(self._load_error)
            return
        try:
            self._store = TechniqueVectorStore.load(data_dir, embedder=self.settings.embedder)
            logger.info(
                "MITRE index loaded: %d techniques (embedder=%s)",
                len(self._store.techniques),
                self._store.backend.name,
            )
        except Exception as exc:  # corrupted index, backend mismatch...
            self._load_error = f"failed to load MITRE index: {exc}"
            logger.warning(self._load_error)

    def retrieve(self, query: str) -> RetrievalResult:
        self._ensure_store()
        if self._store is None:
            return RetrievalResult(
                available=False, query=query, reason=self._load_error or "index unavailable"
            )
        hits = self._store.search(
            query,
            top_k=self.settings.top_k,
            threshold=self.settings.similarity_threshold,
        )
        techniques = [
            RetrievedTechnique(
                id=t.id,
                name=t.name,
                score=score,
                tactics=t.tactics,
                description=t.description,
                detection=t.detection,
            )
            for t, score in hits
        ]
        logger.info(
            "RAG retrieval: %d technique(s) for query '%s' (top_score=%.3f)",
            len(techniques),
            query[:80],
            max((t.score for t in techniques), default=0.0),
        )
        return RetrievalResult(
            available=True,
            query=query,
            retrieved_techniques=techniques,
            embedder_backend=self._store.backend.name,
        )
