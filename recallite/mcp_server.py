"""
recallite.mcp_server — MCP server exposing SANITIZED memory tools.

    recallite mcp --db mem.db --user ali                     # stdio (local)
    recallite mcp --db mem.db --transport http --port 8765   # streamable HTTP

Gives MCP clients (Claude Desktop / Claude Code / ChatGPT developer mode /
Cursor, ...) a persistent memory over your recallite database — with the
Privacy Shield between the store and the model:

    memory_search    search memories; results are privacy-sanitized
    memory_save      save a fact (guardrails + blocklist apply)
    memory_update    supersede an existing fact (history preserved)
    memory_delete    delete one memory by id
    privacy_check    classify text (category counts only, never values)
    policy_status    active privacy policy, store stats

THERE IS NO RESTORE TOOL, BY DESIGN. An MCP tool's output goes to a model;
restoration is a trusted-application privilege served only by the gateway's
/v1/privacy/restore with its own credential. No MCP tool can return raw
SSNs/PANs (structurally excluded) or detokenize anything.

Authentication:
  - stdio transport: the OS user owning the process is the boundary
    (standard for local MCP servers).
  - http transport: Bearer key required (auto-created key file,
    ~/.recallite_mcp_key, chmod 600); server binds 127.0.0.1. Put a real
    reverse proxy with TLS in front for anything beyond localhost.

Honest limitation (document to users): MCP tools cannot intercept text a
person types directly into a native chat interface — the platform receives
that text before any tool runs. Mandatory pre-model sanitization requires
routing the application through `recallite gateway` instead.

Requires: pip install "recallite[mcp]"
"""

from __future__ import annotations

import json
from typing import Optional

from .store import MemoryStore, MEMORY_TYPES
from .privacy import (PrivacyShield, PrivacyError, detect_sensitive,
                      make_name_detector, NEVER_RESTORE, BLOCKING,
                      TOKENIZABLE)

DEFAULT_MCP_KEY_FILE = "~/.recallite_mcp_key"


def build_server(db: str = "recallite.db", user_id: str = "default",
                 privacy: str = "redact", ner: str = "auto"):
    """Create the MCPServer with sanitized tools bound to one store.

    privacy: 'redact' (default) sanitizes every tool output that carries
    memory text; 'off' disables output sanitization (for stores that hold
    no sensitive data — the guardrails on save still apply)."""
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as e:
        raise RuntimeError(
            'MCP server requires the MCP SDK: pip install "recallite[mcp]"'
        ) from e

    store = MemoryStore(db, user_id=user_id)
    shield = None
    if privacy != "off":
        shield = PrivacyShield("redact",
                               name_detector=make_name_detector(ner),
                               strict=(ner == "strict"))

    def _clean(text: str) -> str:
        if shield is None:
            return text
        out, _ = shield.sanitize(text)      # redact mode: no mapping at all
        return out

    srv = MCPServer(
        "recallite",
        instructions=(
            "Persistent, privacy-sanitized memory. Search before answering "
            "questions about the user; save new lasting facts. Sensitive "
            "identifiers in results appear as [SSN]-style placeholders and "
            "cannot be recovered through this server."))

    @srv.tool(description="Search the user's memories. Returns the most "
                          "relevant facts, privacy-sanitized.")
    def memory_search(query: str, top_k: int = 5,
                      memory_type: Optional[str] = None) -> str:
        filters = {"memory_type": memory_type} if memory_type else None
        hits = store.search(query, top_k=min(max(int(top_k), 1), 10),
                            filters=filters)
        if not hits:
            return "No matching memories."
        return "\n".join(
            f"[{m['id']}] ({m['keyword']}, {m['memory_type']}) "
            f"{_clean(m['text'])}" for m in hits)

    @srv.tool(description="Save a lasting fact about the user under a "
                          "short keyword. Guardrails and the prohibited-"
                          "terms blocklist apply.")
    def memory_save(keyword: str, fact: str,
                    memory_type: Optional[str] = None) -> str:
        if memory_type is not None and memory_type not in MEMORY_TYPES:
            return (f"Unknown memory_type {memory_type!r}; "
                    f"use one of {', '.join(MEMORY_TYPES)}.")
        try:
            rec = store.save(fact, keyword=keyword,
                             source="user_conversation",
                             memory_type=memory_type)
        except (ValueError, PermissionError) as e:
            return f"Save refused: {e}"
        return (f"Saved [{rec['id']}] ({rec['keyword']}, "
                f"{rec['memory_type']}): {_clean(rec['text'])}")

    @srv.tool(description="Update a fact: the old memory is superseded "
                          "(kept as history, never retrieved again) and "
                          "the new text becomes current.")
    def memory_update(memory_id: str, keyword: str, fact: str) -> str:
        try:
            rec = store.supersede(memory_id.strip(), fact, keyword=keyword,
                                  source="user_conversation")
        except (ValueError, PermissionError) as e:
            return f"Update refused: {e}"
        return (f"Updated: [{rec['id']}] now current; "
                f"[{memory_id}] kept as history.")

    @srv.tool(description="Delete one memory by its id. Permanent.")
    def memory_delete(memory_id: str) -> str:
        try:
            ok = store.forget(memory_id.strip())
        except PermissionError as e:
            return f"Delete refused: {e}"
        return f"Deleted [{memory_id}]." if ok \
            else f"No memory with id {memory_id}."

    @srv.tool(description="Classify text for sensitive content. Returns "
                          "category counts only — never the values.")
    def privacy_check(text: str) -> str:
        try:
            found = detect_sensitive(
                text,
                name_detector=shield.name_detector if shield else None,
                strict=shield.strict if shield else False)
        except PrivacyError as e:
            return f"Refused: {e}"
        return json.dumps({
            "categories": {k: len(v) for k, v in found.items()},
            "would_block": sorted(set(found) & BLOCKING),
            "never_restored": sorted(set(found) & NEVER_RESTORE)})

    @srv.tool(description="The active privacy policy and store statistics.")
    def policy_status() -> str:
        st = store.stats()
        return json.dumps({
            "privacy_output_mode": privacy,
            "name_detection": ner if shield else "off",
            "never_restore_categories": sorted(NEVER_RESTORE),
            "blocking_categories": sorted(BLOCKING),
            "tokenizable_categories": sorted(TOKENIZABLE),
            "restore_tool_exists": False,
            "memories": st["count"], "superseded": st["superseded"],
            "note": ("MCP cannot intercept text typed directly into a "
                     "native chat interface; use `recallite gateway` for "
                     "mandatory pre-model sanitization.")})

    return srv


class _BearerAuth:
    """Starlette middleware: require Authorization: Bearer <key>."""

    def __init__(self, app, key: str):
        self.app = app
        self.key = key

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            headers = {k.decode().lower(): v.decode()
                       for k, v in scope.get("headers", [])}
            if headers.get("authorization") != f"Bearer {self.key}":
                body = json.dumps({"error": "Missing or invalid API key."}) \
                    .encode()
                await send({"type": "http.response.start", "status": 401,
                            "headers": [(b"content-type",
                                         b"application/json")]})
                await send({"type": "http.response.body", "body": body})
                return
        await self.app(scope, receive, send)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="recallite mcp")
    p.add_argument("--db", default="recallite.db")
    p.add_argument("--user", default="default")
    p.add_argument("--transport", choices=["stdio", "http"],
                   default="stdio")
    p.add_argument("--port", type=int, default=8765)
    p.add_argument("--privacy", choices=["redact", "off"], default="redact")
    p.add_argument("--ner", choices=["auto", "off", "strict"],
                   default="auto")
    p.add_argument("--key-file", default=None,
                   help="http transport: Bearer key file "
                        f"(default {DEFAULT_MCP_KEY_FILE})")
    a = p.parse_args(argv)

    try:
        srv = build_server(a.db, a.user, privacy=a.privacy, ner=a.ner)
    except (RuntimeError, PrivacyError) as e:
        print(f"[mcp] refusing to start: {e}")
        return 1

    if a.transport == "stdio":
        srv.run("stdio")
        return 0

    from .gateway import load_or_create_key
    key = load_or_create_key(a.key_file, DEFAULT_MCP_KEY_FILE, "mcp")
    import uvicorn
    app = _BearerAuth(srv.streamable_http_app(), key)
    print(f"[mcp] sanitized memory tools on "
          f"http://127.0.0.1:{a.port}/mcp (Bearer auth required)")
    uvicorn.run(app, host="127.0.0.1", port=a.port, log_level="warning")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
