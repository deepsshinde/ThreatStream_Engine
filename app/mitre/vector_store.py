"""Vector storage: FAISS if available, NumPy fallback, same interface.

Vectors are L2-normalized, so inner product == cosine similarity. Layout on
disk (matches the project spec):

    data/mitre/
    ├── techniques.json           # full technique records
    ├── metadata.json             # backend, model, dim, count, embedding model
    ├── index.faiss               # when faiss-cpu is installed (preferred)
    └── vectors.npy               # NumPy fallback otherwise

The interface is tiny on purpose: build/save/load/search. If FAISS is
unavailable the NumPy brute-force path is used (fine for ~1k techniques);
FAISS exists for when the KB grows.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Sequence

import numpy as np

from app.exceptions import ThreatStreamError
from app.mitre.embeddings import EmbeddingBackend, get_backend
from app.mitre.loader import Technique

logger = logging.getLogger("threatstream.mitre.vectorstore")

try:
    import faiss

    HAVE_FAISS = True
except ImportError:  # pragma: no cover - environment dependent
    faiss = None
    HAVE_FAISS = False


class TechniqueVectorStore:
    def __init__(
        self,
        backend: EmbeddingBackend,
        vectors: np.ndarray,
        techniques: list[Technique],
        source: str,
    ):
        self.backend = backend
        self.vectors = vectors.astype(np.float32)
        self.techniques = techniques
        self.source = source
        self._index = None
        if HAVE_FAISS and len(techniques):
            self._index = faiss.IndexFlatIP(backend.dim)
            self._index.add(self.vectors)

    # ------------------------------------------------------------------ #
    def search(self, text: str, top_k: int = 5, threshold: float = 0.0) -> list[tuple[Technique, float]]:
        if not self.techniques:
            return []
        query = self.backend.embed([text]).astype(np.float32)
        return self.search_vector(query[0], top_k=top_k, threshold=threshold)

    def search_vector(self, query: np.ndarray, top_k: int = 5, threshold: float = 0.0) -> list[tuple[Technique, float]]:
        if not self.techniques:
            return []
        q = query.reshape(1, -1).astype(np.float32)
        if self._index is not None:
            scores, idxs = self._index.search(q, min(top_k, len(self.techniques)))
            pairs = list(zip(idxs[0].tolist(), scores[0].tolist(), strict=True))
        else:
            sims = self.vectors @ q[0]
            idxs = np.argsort(-sims)[: min(top_k, len(self.techniques))]
            pairs = [(int(i), float(sims[i])) for i in idxs]
        results = []
        for idx, score in pairs:
            if idx < 0 or score < threshold:
                continue
            results.append((self.techniques[idx], float(score)))
        return results

    # ------------------------------------------------------------------ #
    @classmethod
    def build(
        cls,
        techniques: Sequence[Technique],
        backend: EmbeddingBackend,
        source: str = "unknown",
    ) -> "TechniqueVectorStore":
        texts = [t.text_for_embedding() for t in techniques]
        logger.info("Embedding %d techniques with backend=%s ...", len(texts), backend.name)
        vectors = backend.embed(texts)
        return cls(backend=backend, vectors=vectors, techniques=list(techniques), source=source)

    def save(self, data_dir: str | Path) -> dict[str, Any]:
        data_dir = Path(data_dir)
        data_dir.mkdir(parents=True, exist_ok=True)
        metadata = {
            "embedder_backend": self.backend.name,
            "embedder_model": self.backend.model_name,
            "dim": self.backend.dim,
            "count": len(self.techniques),
            "source": self.source,
            "index_file": "index.faiss" if self._index is not None else "vectors.npy",
        }
        (data_dir / "techniques.json").write_text(
            json.dumps([t.to_dict() for t in self.techniques], indent=1), encoding="utf-8"
        )
        if self._index is not None:
            faiss.write_index(self._index, str(data_dir / "index.faiss"))
            np.save(data_dir / "vectors.npy", self.vectors)  # useful for tooling/debug
        else:
            np.save(data_dir / "vectors.npy", self.vectors)
        (data_dir / "metadata.json").write_text(json.dumps(metadata, indent=1), encoding="utf-8")
        logger.info("Vector store saved to %s (%s)", data_dir, metadata)
        return metadata

    @classmethod
    def load(cls, data_dir: str | Path, embedder: str = "auto") -> "TechniqueVectorStore":
        data_dir = Path(data_dir)
        metadata_file = data_dir / "metadata.json"
        techniques_file = data_dir / "techniques.json"
        if not metadata_file.is_file() or not techniques_file.is_file():
            raise ThreatStreamError(
                f"MITRE index not found in {data_dir}. Build it with: "
                f"python -m app.cli build-mitre-index"
            )
        metadata = json.loads(metadata_file.read_text(encoding="utf-8"))
        wanted = metadata.get("embedder_backend", "auto")
        if embedder != "auto" and embedder != wanted:
            raise ThreatStreamError(
                f"index was built with embedder '{wanted}', but '{embedder}' requested. "
                f"Rebuild: python -m app.cli build-mitre-index --embedder {embedder}"
            )
        backend = get_backend(wanted, dim=int(metadata.get("dim", 0)) or None)
        if backend.dim != int(metadata.get("dim", 0)):
            raise ThreatStreamError(
                f"embedding dimension mismatch: index={metadata.get('dim')} backend={backend.dim}. Rebuild the index."
            )
        vectors = np.load(data_dir / "vectors.npy").astype(np.float32)
        techniques = [
            Technique(**{k: t.get(k, [] if k == "tactics" else "") for k in ("id", "name", "description", "tactics", "detection", "url")})
            for t in json.loads(techniques_file.read_text(encoding="utf-8"))
        ]
        store = cls(backend=backend, vectors=vectors, techniques=techniques, source=metadata.get("source", "unknown"))
        if store._index is not None and store._index.ntotal != len(techniques):
            store._index = faiss.IndexFlatIP(backend.dim)
            store._index.add(store.vectors)
        return store

    @staticmethod
    def is_available(data_dir: str | Path) -> bool:
        data_dir = Path(data_dir)
        return (data_dir / "metadata.json").is_file() and (data_dir / "techniques.json").is_file()
