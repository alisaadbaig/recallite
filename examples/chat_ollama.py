"""Run an interactive memory-chat with Ollama.

    ollama pull llama3.2
    python examples/chat_ollama.py
"""
from recallite import MemoryStore, MemoryAgent, OllamaBackend

agent = MemoryAgent(
    MemoryStore("mem.db", user_id="ali"),
    OllamaBackend("llama3.2"),
)
agent.repl()
