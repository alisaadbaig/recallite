"""
recallite.adapters — one interface, any backend, now with streaming + history.

All backends implement:
    .chat(system, user, history=None)         -> str
    .chat_stream(system, user, history=None)  -> generator of str chunks
history = list of {"role": "user"|"assistant", "content": str}
"""

from __future__ import annotations

import json
import urllib.request
from typing import Iterator, Optional


def _messages(system: str, user: str, history: Optional[list]) -> list:
    msgs = [{"role": "system", "content": system}]
    msgs += history or []
    msgs.append({"role": "user", "content": user})
    return msgs


def _request(url: str, payload: dict, headers: Optional[dict] = None,
             timeout: int = 300):
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    return urllib.request.urlopen(req, timeout=timeout)


def _post_json(url, payload, headers=None, timeout=300,
               retries: int = 2) -> dict:
    import time as _t
    last = None
    for attempt in range(retries + 1):
        try:
            with _request(url, payload, headers, timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError) as e:  # type: ignore
            last = e
            if attempt < retries:
                _t.sleep(1.5 ** attempt)
    raise ConnectionError(
        f"Backend unreachable at {url} after {retries+1} attempts: {last}")


class BaseBackend:
    def chat(self, system_prompt: str, user_message: str,
             history: Optional[list] = None) -> str:
        raise NotImplementedError

    def chat_stream(self, system_prompt: str, user_message: str,
                    history: Optional[list] = None) -> Iterator[str]:
        # default fallback: yield the whole reply at once
        yield self.chat(system_prompt, user_message, history)


class OllamaBackend(BaseBackend):
    def __init__(self, model: str = "llama3.2",
                 host: str = "http://localhost:11434",
                 options: Optional[dict] = None):
        self.model = model
        self.url = host.rstrip("/") + "/api/chat"
        self.options = options or {}

    def chat(self, system_prompt, user_message, history=None) -> str:
        data = _post_json(self.url, {
            "model": self.model, "stream": False, "options": self.options,
            "messages": _messages(system_prompt, user_message, history)})
        return data["message"]["content"]

    def chat_stream(self, system_prompt, user_message, history=None):
        payload = {"model": self.model, "stream": True, "options": self.options,
                   "messages": _messages(system_prompt, user_message, history)}
        with _request(self.url, payload) as resp:
            for line in resp:
                if not line.strip():
                    continue
                chunk = json.loads(line)
                piece = chunk.get("message", {}).get("content", "")
                if piece:
                    yield piece
                if chunk.get("done"):
                    break


class OpenAICompatBackend(BaseBackend):
    """vLLM, LM Studio, llama.cpp server, OpenAI, Groq, Together..."""

    def __init__(self, model: str, base_url: str = "http://localhost:8000/v1",
                 api_key: str = "not-needed", temperature: float = 0.7):
        self.model = model
        self.url = base_url.rstrip("/") + "/chat/completions"
        self.api_key = api_key
        self.temperature = temperature

    def _headers(self):
        return {"Authorization": f"Bearer {self.api_key}"}

    def chat(self, system_prompt, user_message, history=None) -> str:
        data = _post_json(self.url, {
            "model": self.model, "temperature": self.temperature,
            "messages": _messages(system_prompt, user_message, history)},
            headers=self._headers())
        return data["choices"][0]["message"]["content"]

    def chat_stream(self, system_prompt, user_message, history=None):
        payload = {"model": self.model, "temperature": self.temperature,
                   "stream": True,
                   "messages": _messages(system_prompt, user_message, history)}
        with _request(self.url, payload, headers=self._headers()) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if data == "[DONE]":
                    break
                delta = (json.loads(data)["choices"][0]
                         .get("delta", {}).get("content"))
                if delta:
                    yield delta


class AnthropicBackend(BaseBackend):
    """
    Claude via Anthropic's native Messages API (streaming supported).

    Get an API key at https://console.anthropic.com and either pass it
    or set the ANTHROPIC_API_KEY environment variable.

        backend = AnthropicBackend("claude-sonnet-4-6")
    """

    def __init__(self, model: str = "claude-sonnet-4-6",
                 api_key: Optional[str] = None,
                 base_url: str = "https://api.anthropic.com",
                 max_tokens: int = 1024, temperature: float = 0.7):
        import os
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "Anthropic API key missing. Pass api_key=... or set the "
                "ANTHROPIC_API_KEY environment variable.")
        self.url = base_url.rstrip("/") + "/v1/messages"
        self.max_tokens = max_tokens
        self.temperature = temperature

    def _headers(self):
        return {"x-api-key": self.api_key,
                "anthropic-version": "2023-06-01"}

    def _payload(self, system, user, history, stream=False):
        # Anthropic takes `system` separately; messages hold the turns
        msgs = (history or []) + [{"role": "user", "content": user}]
        p = {"model": self.model, "max_tokens": self.max_tokens,
             "temperature": self.temperature,
             "system": system, "messages": msgs}
        if stream:
            p["stream"] = True
        return p

    def chat(self, system_prompt, user_message, history=None) -> str:
        data = _post_json(self.url,
                          self._payload(system_prompt, user_message, history),
                          headers=self._headers())
        return "".join(b.get("text", "") for b in data.get("content", [])
                       if b.get("type") == "text")

    def chat_stream(self, system_prompt, user_message, history=None):
        payload = self._payload(system_prompt, user_message, history,
                                stream=True)
        with _request(self.url, payload, headers=self._headers()) as resp:
            for raw in resp:
                line = raw.decode("utf-8").strip()
                if not line.startswith("data:"):
                    continue
                data = line[5:].strip()
                if not data:
                    continue
                event = json.loads(data)
                if event.get("type") == "content_block_delta":
                    piece = event.get("delta", {}).get("text", "")
                    if piece:
                        yield piece
                elif event.get("type") == "message_stop":
                    break


class HuggingFaceBackend(BaseBackend):
    """In-process transformers pipeline. pip install recallite[huggingface]"""

    def __init__(self, model_id: str, device_map: str = "auto",
                 max_new_tokens: int = 512, **pipeline_kwargs):
        try:
            from transformers import pipeline
        except ImportError as e:
            raise ImportError(
                "HuggingFaceBackend requires: pip install transformers torch"
            ) from e
        self.pipe = pipeline("text-generation", model=model_id,
                             device_map=device_map, **pipeline_kwargs)
        self.max_new_tokens = max_new_tokens

    def chat(self, system_prompt, user_message, history=None) -> str:
        out = self.pipe(_messages(system_prompt, user_message, history),
                        max_new_tokens=self.max_new_tokens,
                        return_full_text=False)
        return out[0]["generated_text"]
