"""Embedding backends.

Two interchangeable implementations of the same interface:

* :class:`SentenceTransformerBackend` - the real deal: a local
  sentence-transformers model (default ``all-MiniLM-L6-v2``, 384-dim,
  ~90 MB download on first use, runs on CPU). This is what you want for the
  portfolio demo.
* :class:`HashingVectorBackend` - a deterministic feature-hashing encoder
  (zero dependencies beyond numpy, zero downloads). It is *not* a semantic
  model; it exists so tests and air-gapped environments can exercise the
  full RAG code path. It is honestly labelled everywhere it is used.

``--embedder auto`` prefers sentence-transformers and degrades to hashing
with a loud warning. The chosen backend + dimension are recorded in
``metadata.json`` next to the index; the retriever refuses to load a
mismatched index (dim/backend) with a clear rebuild hint.
"""

from __future__ import annotations

import hashlib
import logging
import re
from typing import Protocol, Sequence, runtime_checkable

import numpy as np

logger = logging.getLogger("threatstream.mitre.embeddings")

_WORD_RE = re.compile(r"[a-z0-9\.\-_/]+")


@runtime_checkable
class EmbeddingBackend(Protocol):
    name: str
    model_name: str
    dim: int

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        """Return an (n, dim) float32 array of L2-normalized vectors."""
        ...


class HashingVectorBackend:
    """Deterministic feature hashing over unigrams + bigrams (offline, fast)."""

    name = "hashing"
    model_name = "deterministic-feature-hashing"

    def __init__(self, dim: int = 256):
        self.dim = dim

    def _tokenize(self, text: str) -> list[str]:
        tokens = _WORD_RE.findall(text.lower())
        bigrams = [f"{tokens[i]}:{tokens[i+1]}" for i in range(len(tokens) - 1)]
        return tokens + bigrams

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        vectors = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for token in self._tokenize(text):
                digest = hashlib.sha256(token.encode("utf-8")).digest()
                idx = int.from_bytes(digest[:4], "little") % self.dim
                sign = 1.0 if digest[4] % 2 == 0 else -1.0
                vectors[row, idx] += sign
        norms = np.linalg.norm(vectors, axis=1, keepdims=True)
        norms[norms == 0] = 1.0
        return (vectors / norms).astype(np.float32)


class SentenceTransformerBackend:
    """Local sentence-transformers encoder (e.g. all-MiniLM-L6-v2, CPU)."""

    name = "sentence-transformers"

    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2"):
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as exc:
            raise RuntimeError(
                "sentence-transformers is not installed. "
                "pip install sentence-transformers, or use --embedder hashing"
            ) from exc
        self.model_name = model_name
        self._model = SentenceTransformer(model_name)
        self.dim = int(self._model.get_sentence_embedding_dimension())
        logger.info("Loaded embedding model %s (dim=%d)", model_name, self.dim)

    def embed(self, texts: Sequence[str]) -> np.ndarray:
        vectors = self._model.encode(
            list(texts), normalize_embeddings=True, convert_to_numpy=True, show_progress_bar=False
        )
        return vectors.astype(np.float32)


def sentence_transformers_available() -> bool:
    try:
        import sentence_transformers  # noqa: F401

        return True
    except ImportError:
        return False


def get_backend(
    name: str = "auto",
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2",
    dim: int | None = None,
) -> EmbeddingBackend:
    if name == "hashing":
        return HashingVectorBackend(dim=dim or 256)
    if name == "sentence-transformers":
        return SentenceTransformerBackend(model_name)
    if name == "auto":
        if sentence_transformers_available():
            return SentenceTransformerBackend(model_name)
        logger.warning(
            "sentence-transformers not installed - using deterministic hashing embedder "
            "(RAG retrieval quality will be lower; this is the documented fallback)"
        )
        return HashingVectorBackend()
    raise ValueError(f"unknown embedder '{name}'")
