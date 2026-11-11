"""
recallite.embeddings — pluggable embedding providers for semantic search.

Any object with  .encode(list[str]) -> list[list[float]]  works:

    SentenceTransformerEmbedder()   pip install "recallite[semantic]"
    OllamaEmbedder()                zero installs if you already run Ollama
    <your own>                      any callable class with .encode()

Vectors are L2-normalized so cosine similarity is a plain dot product.
"""

from __future__ import annotations

import json
import math
import urllib.request
from typing import Optional


def _normalize(vec: list[float]) -> list[float]:
    n = math.sqrt(sum(x * x for x in vec)) or 1.0
    return [x / n for x in vec]


class SentenceTransformerEmbedder:
    """Local embedding model via sentence-transformers (lazy-loaded)."""

    def __init__(self, model: str = "sentence-transformers/all-MiniLM-L6-v2"):
        self.model_name = model
        self._model = None

    def _load(self):
        if self._model is None:
            from sentence_transformers import SentenceTransformer
            self._model = SentenceTransformer(self.model_name)
        return self._model

    def encode(self, texts: list[str]) -> list[list[float]]:
        vecs = self._load().encode(texts, normalize_embeddings=True)
        return [list(map(float, v)) for v in vecs]


class OllamaEmbedder:
    """Embeddings from a local Ollama server — no Python packages needed.

        ollama pull nomic-embed-text
        store = MemoryStore("mem.db", embedder=OllamaEmbedder())
    """

    def __init__(self, model: str = "nomic-embed-text",
                 host: str = "http://localhost:11434", timeout: int = 60):
        self.model = model
        self.url = host.rstrip("/") + "/api/embed"
        self.timeout = timeout

    def encode(self, texts: list[str]) -> list[list[float]]:
        body = json.dumps({"model": self.model, "input": texts}).encode()
        req = urllib.request.Request(self.url, data=body, method="POST")
        req.add_header("Content-Type", "application/json")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        return [_normalize(v) for v in data["embeddings"]]


def resolve_embedder(use_embeddings: bool, embedder,
                     embedding_model: str) -> Optional[object]:
    """Store helper: explicit embedder wins; use_embeddings=True implies
    sentence-transformers; otherwise no semantic layer."""
    if embedder is not None:
        return embedder
    if use_embeddings:
        return SentenceTransformerEmbedder(embedding_model)
    return None


class CrossEncoderReranker:
    """Optional precision reranker (pip install "recallite[semantic]").

        store = MemoryStore("mem.db", reranker=CrossEncoderReranker())

    Scores (query, text) pairs jointly — slower than bi-encoder retrieval
    but sharper at the top of the list. Lazy-loaded; a failure falls back
    to fusion order (retrieval never breaks)."""

    def __init__(self, model: str = "cross-encoder/ms-marco-MiniLM-L-6-v2"):
        self.model_name = model
        self._model = None

    def _load(self):
        if self._model is None:
            from sentence_transformers import CrossEncoder
            self._model = CrossEncoder(self.model_name)
        return self._model

    def rank(self, query: str, texts: list[str]) -> list[float]:
        return [float(s) for s in
                self._load().predict([(query, t) for t in texts])]
