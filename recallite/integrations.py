"""
recallite.integrations — drop recallite into LangChain and LlamaIndex.

Both wrappers are thin: recallite's own pipeline (hybrid retrieval,
filters, temporal ranking, provenance) does the work, and results arrive
as the framework's native document type with the explain signals in
metadata. Imports are lazy — the core stays zero-dependency, and each
factory raises a clear install hint when its framework is missing.

    # LangChain (pip install langchain-core)
    retriever = as_langchain_retriever(store, top_k=5,
                                       filters={"memory_type": "preference"})
    docs = retriever.invoke("what food does the user like?")

    # LlamaIndex (pip install llama-index-core)
    retriever = as_llamaindex_retriever(store, top_k=5)
    nodes = retriever.retrieve("what food does the user like?")

Privacy note: pass `sanitize=True` to redact sensitive identifiers in
retrieved text before it reaches a chain or index pipeline (uses the
Privacy Shield in redact mode; SSN/PAN are always placeholders).
"""

from __future__ import annotations

from typing import Any, Optional


def _maybe_shield(sanitize: bool, ner: str):
    if not sanitize:
        return None
    from .privacy import PrivacyShield, make_name_detector
    return PrivacyShield("redact", name_detector=make_name_detector(ner),
                         strict=(ner == "strict"))


def _hit_meta(m: dict) -> dict:
    meta = {"id": m["id"], "keyword": m["keyword"],
            "memory_type": m["memory_type"], "source": m["source"],
            "confidence": m["confidence"], "importance": m["importance"],
            "created_at": m["created_at"]}
    if "explain" in m:
        meta["explain"] = m["explain"]
    return meta


def as_langchain_retriever(store, top_k: int = 5, strategy: str = "auto",
                           filters: Optional[dict] = None,
                           sanitize: bool = False, ner: str = "auto"):
    """A LangChain BaseRetriever over a MemoryStore."""
    try:
        from langchain_core.retrievers import BaseRetriever
        from langchain_core.documents import Document
        from langchain_core.callbacks import (
            CallbackManagerForRetrieverRun)
    except ImportError as e:
        raise ImportError(
            "LangChain integration requires: pip install langchain-core"
        ) from e

    shield = _maybe_shield(sanitize, ner)

    class RecalliteRetriever(BaseRetriever):
        store: Any
        top_k: int = 5
        strategy: str = "auto"
        filters: Optional[dict] = None

        model_config = {"arbitrary_types_allowed": True}

        def _get_relevant_documents(
                self, query: str, *,
                run_manager: CallbackManagerForRetrieverRun
        ) -> list[Document]:
            hits = self.store.search(query, top_k=self.top_k,
                                     strategy=self.strategy,
                                     filters=self.filters, explain=True)
            docs = []
            for m in hits:
                text = m["text"]
                if shield is not None:
                    text, _ = shield.sanitize(text)
                docs.append(Document(page_content=text,
                                     metadata=_hit_meta(m)))
            return docs

    return RecalliteRetriever(store=store, top_k=top_k,
                             strategy=strategy, filters=filters)


def as_llamaindex_retriever(store, top_k: int = 5, strategy: str = "auto",
                            filters: Optional[dict] = None,
                            sanitize: bool = False, ner: str = "auto"):
    """A LlamaIndex BaseRetriever over a MemoryStore."""
    try:
        from llama_index.core.retrievers import BaseRetriever
        from llama_index.core.schema import (NodeWithScore, TextNode,
                                             QueryBundle)
    except ImportError as e:
        raise ImportError(
            "LlamaIndex integration requires: pip install llama-index-core"
        ) from e

    shield = _maybe_shield(sanitize, ner)

    class RecalliteLIRetriever(BaseRetriever):
        def __init__(self):
            super().__init__()
            self._store = store

        def _retrieve(self, query_bundle: QueryBundle
                      ) -> list[NodeWithScore]:
            hits = self._store.search(query_bundle.query_str, top_k=top_k,
                                      strategy=strategy, filters=filters,
                                      explain=True)
            out = []
            for m in hits:
                text = m["text"]
                if shield is not None:
                    text, _ = shield.sanitize(text)
                node = TextNode(text=text, id_=m["id"],
                                metadata=_hit_meta(m))
                score = m.get("explain", {}).get("fused_score", 0.0)
                out.append(NodeWithScore(node=node, score=score))
            return out

    return RecalliteLIRetriever()
