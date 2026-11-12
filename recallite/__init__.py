"""
recallite — Give ANY LLM permanent memory. No fine-tuning, no model changes.
"""

from .store import MemoryStore
from .agent import MemoryAgent
from .tasks import TaskManager, fetch_url_text
from .embeddings import (SentenceTransformerEmbedder, OllamaEmbedder,
                         CrossEncoderReranker)
from .privacy import (PrivacyShield, PrivacySession, PrivacyError,
                      StreamScanner, PresidioDetector)
from .integrations import as_langchain_retriever, as_llamaindex_retriever
from .guardrails import Guardrails
from .adapters import (
    BaseBackend, OllamaBackend, OpenAICompatBackend,
    AnthropicBackend, HuggingFaceBackend,
)

__version__ = "0.17.1"
__all__ = ["MemoryStore", "MemoryAgent", "Guardrails", "BaseBackend",
           "OllamaBackend", "OpenAICompatBackend", "AnthropicBackend",
           "HuggingFaceBackend", "TaskManager", "fetch_url_text",
           "SentenceTransformerEmbedder", "OllamaEmbedder", "CrossEncoderReranker",
           "PrivacyShield", "PrivacySession", "PrivacyError",
           "StreamScanner", "PresidioDetector",
           "as_langchain_retriever", "as_llamaindex_retriever"]
