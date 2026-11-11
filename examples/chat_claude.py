"""Chat with memory using Claude (Anthropic).

    export ANTHROPIC_API_KEY=sk-ant-...   # get one at console.anthropic.com
    python3 examples/chat_claude.py
"""
from recallite import MemoryStore, MemoryAgent, AnthropicBackend, Guardrails

backend = AnthropicBackend(
    model="claude-sonnet-4-6",     # reads ANTHROPIC_API_KEY from environment
)

agent = MemoryAgent(
    MemoryStore("claude_memory.db", user_id="ali",
                guardrails=Guardrails(pii_mode="redact")),
    backend,
)
agent.repl()

# The point of recallite: this claude_memory.db is the SAME format as the
# Ollama/vLLM/OpenAI examples. Point them all at one db file and every
# model shares one memory of you.
