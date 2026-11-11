"""Chat with memory using OpenAI (ChatGPT models).

    export OPENAI_API_KEY=sk-...        # get one at platform.openai.com
    python3 examples/chat_openai.py
"""
import os
from recallite import MemoryStore, MemoryAgent, OpenAICompatBackend, Guardrails

backend = OpenAICompatBackend(
    model="gpt-4o-mini",                       # any chat model you have access to
    base_url="https://api.openai.com/v1",
    api_key=os.environ["OPENAI_API_KEY"],
)

agent = MemoryAgent(
    MemoryStore("openai_memory.db", user_id="ali",
                guardrails=Guardrails(pii_mode="redact")),
    backend,
)
agent.repl()
