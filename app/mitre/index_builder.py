"""Builds the MITRE vector index (used by script + CLI command)."""

from __future__ import annotations

import logging
import time
from pathlib import Path

from app.config import Settings
from app.mitre.embeddings import get_backend
from app.mitre.loader import load_techniques
from app.mitre.vector_store import TechniqueVectorStore

logger = logging.getLogger("threatstream.mitre.builder")


def build_mitre_index(
    settings: Settings,
    source: str = "auto",
    embedder_name: str | None = None,
    stix_file: str | Path | None = None,
) -> dict:
    started = time.perf_counter()
    builtin_file = settings.rag.data_dir / "builtin_techniques.json"
    if not Path(builtin_file).is_file():
        # fallback if data_dir was overridden
        builtin_file = settings.project_root / "data" / "mitre" / "builtin_techniques.json"

    techniques, source_desc = load_techniques(
        source=source, stix_file=stix_file, builtin_file=builtin_file
    )
    backend = get_backend(embedder_name or settings.rag.embedder)
    store = TechniqueVectorStore.build(techniques, backend, source=source_desc)
    metadata = store.save(settings.rag.data_dir)
    duration = time.perf_counter() - started
    result = {
        "techniques": len(techniques),
        "source": source_desc,
        "embedder_backend": backend.name,
        "embedder_model": backend.model_name,
        "dim": backend.dim,
        "data_dir": str(settings.rag.data_dir),
        "duration_sec": round(duration, 2),
    }
    logger.info("MITRE index built: %s", result)
    return result
