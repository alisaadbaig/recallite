"""Chat with memory using a Hugging Face model fully in-process (no server).

    pip install "recallite[huggingface]"
    python3 examples/chat_hf.py
"""
from recallite import MemoryStore, MemoryAgent, HuggingFaceBackend

agent = MemoryAgent(
    MemoryStore("hf_memory.db", user_id="ali"),
    HuggingFaceBackend("Qwen/Qwen2.5-1.5B-Instruct"),
)
agent.repl()
