"""Chat with memory against a local vLLM server.

Start the server first, e.g.:
    vllm serve openai/gpt-oss-20b --gpu-memory-utilization 0.90 \
         --max-model-len 32768

Then:  python3 examples/chat_vllm.py
"""
from recallite import MemoryStore, MemoryAgent, OpenAICompatBackend, Guardrails

backend = OpenAICompatBackend(
    model="openai/gpt-oss-20b",          # must match `vllm serve` exactly
    base_url="http://localhost:8000/v1",
)

guard = Guardrails(
    pii_mode="redact",                   # allow | warn | redact | block
    blocklist=[],                        # e.g. ["topsecret", "projectx"]
    max_length=2000,
)

agent = MemoryAgent(
    MemoryStore("vllm_memory.db", user_id="ali", guardrails=guard),
    backend,
)
agent.repl()
