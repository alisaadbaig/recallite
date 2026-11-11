"""
recallite.gateway — OpenAI-compatible privacy gateway (stdlib only).

    recallite gateway --upstream http://localhost:8000/v1 --mode tokenize

Applications point their OpenAI-compatible client at the gateway instead of
the model. Every permitted request field is sanitized by the Privacy Shield
engine BEFORE leaving for the upstream model; model output (including tool
calls) is DLP-scanned on the way back. Restoration is a separate privilege
with its own credential — chat clients cannot restore anything.

Identity model (v0.14):
    - GATEWAY keys (--key-file, default ~/.recallite_gateway_key): one per
      line, optionally "key tenant-label". They authorize chat and
      /v1/privacy/check only. Tenant identity is resolved SERVER-SIDE from
      the key — never from a client-supplied field.
    - RESTORE keys (--restore-key-file, default ~/.recallite_restore_key):
      a distinct credential for trusted restoration services. Lines:
      "key [tenant=label] [categories=email,person] [destinations=app]".
      Only /v1/privacy/restore accepts them; a gateway key there is 403.
    - No inline restoration exists on the chat path. SSN/PAN remain
      structurally unrestorable for every identity (recallite/privacy.py).

Session model (v0.14):
    - The gateway MINTS session ids (secrets.token_urlsafe) and returns
      them in the response ("recallite.session"). A client may continue a
      session by sending "recallite_session"; the gateway enforces that the
      session is owned by the calling key's tenant — an unknown or
      foreign id is refused, never silently created.
    - Sessions are RAM-only, TTL-bound, count-capped, and each carries its
      own lock for concurrency-safe mapping access. Multi-instance note:
      sessions are per-process; run one instance or use sticky routing.

Schema handling (v0.14):
    - Requests: only known top-level fields, message fields, content part
      types, tool/tool_call shapes are accepted; anything unknown is
      REJECTED EXPLICITLY (400 naming the field), never forwarded.
      Supported agent structures (tools, tool_calls, tool role, name,
      tool_call_id) are preserved with every string sanitized.
    - Responses: only known fields are forwarded; unknown message fields
      and logprobs are STRIPPED and reported. Assistant text, tool-call
      arguments, function_call arguments, and refusal strings are all
      DLP-scanned before the client sees them.

Fail closed everywhere: CVV/PIN content, uninspectable parts, detector
failures (strict NER mode), oversized bodies, unknown schema, expired or
foreign sessions. Logs carry categories and counts, never values.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import threading
import time
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .privacy import (PrivacyShield, PrivacySession, PrivacyError,
                      detect_sensitive, make_name_detector,
                      NEVER_RESTORE, BLOCKING)

MAX_BODY = 2 * 1024 * 1024
DEFAULT_KEY_FILE = "~/.recallite_gateway_key"
DEFAULT_RESTORE_KEY_FILE = "~/.recallite_restore_key"
log = logging.getLogger("recallite.gateway")

ALLOWED_TOP = {"model", "messages", "temperature", "max_tokens", "top_p",
               "stop", "presence_penalty", "frequency_penalty", "seed", "n",
               "stream", "user", "recallite_session", "tools", "tool_choice",
               "response_format"}
FORWARD_TOP = ("model", "temperature", "max_tokens", "top_p", "stop",
               "presence_penalty", "frequency_penalty", "seed", "n",
               "tools", "tool_choice", "response_format")
ALLOWED_ROLES = {"system", "user", "assistant", "tool", "developer"}
ALLOWED_MSG_FIELDS = {"role", "content", "name", "tool_call_id",
                      "tool_calls"}
RESP_MSG_FIELDS = {"role", "content", "tool_calls", "function_call",
                   "refusal"}


def _ident(key: str) -> str:
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def load_or_create_key(path: str | None, default_path: str,
                       label: str) -> str:
    p = Path(path or default_path).expanduser()
    if p.exists():
        first = p.read_text(encoding="utf-8").strip().splitlines()
        if first and len(first[0].split()[0]) >= 16:
            return first[0].split()[0]
    key = secrets.token_urlsafe(32)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(key + "\n", encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass
    print(f"[gateway] created {label} key file: {p}")
    return key


def _parse_key_file(path: Path) -> dict:
    """'key [k=v]...' per line -> {key: {options}}."""
    out = {}
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        parts = line.strip().split()
        if not parts or parts[0].startswith("#"):
            continue
        opts = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                opts[k] = v
            else:
                opts["tenant"] = p
        out[parts[0]] = opts
    return out


class _Session:
    __slots__ = ("psession", "tenant", "lock")

    def __init__(self, psession: PrivacySession, tenant: str):
        self.psession = psession
        self.tenant = tenant
        self.lock = threading.Lock()


class GatewayState:
    def __init__(self, upstream: str, mode: str, gateway_keys: dict,
                 restore_keys: dict, restore_allow: set[str],
                 restore_destinations: set[str], session_ttl: int = 900,
                 ner: str = "auto"):
        self.upstream = upstream.rstrip("/")
        self.mode = mode
        detector = make_name_detector(ner)   # strict raises here: fail closed
        self.shield = PrivacyShield(mode, name_detector=detector,
                                    strict=(ner == "strict"))
        self.gateway_keys = gateway_keys        # key -> {tenant?}
        self.restore_keys = restore_keys        # key -> {tenant?, categories?, destinations?}
        self.restore_allow = ({c.lower() for c in restore_allow}
                              - set(NEVER_RESTORE) - set(BLOCKING))
        self.restore_destinations = restore_destinations or {"app"}
        self.session_ttl = session_ttl
        self.sessions: dict[str, _Session] = {}
        self.lock = threading.Lock()

    # -- identities ------------------------------------------------------

    def gateway_tenant(self, key: str) -> str | None:
        if key not in self.gateway_keys:
            return None
        return self.gateway_keys[key].get("tenant") or _ident(key)

    def restore_identity(self, key: str) -> dict | None:
        return self.restore_keys.get(key)

    # -- sessions --------------------------------------------------------

    def mint_session(self, tenant: str) -> str:
        sid = secrets.token_urlsafe(24)
        with self.lock:
            for k in [k for k, s in self.sessions.items()
                      if s.psession.expired()]:
                del self.sessions[k]
            if len(self.sessions) >= 1000:
                oldest = min(self.sessions,
                             key=lambda k: self.sessions[k].psession.created)
                del self.sessions[oldest]
            self.sessions[sid] = _Session(
                PrivacySession(ttl_seconds=self.session_ttl), tenant)
        return sid

    def get_session(self, sid: str, tenant: str) -> _Session | None:
        """Owner-enforced lookup: foreign or expired sessions are None."""
        with self.lock:
            s = self.sessions.get(sid)
            if s is None or s.psession.expired():
                return None
            if s.tenant != tenant:
                return None
        return s


class GatewayHandler(BaseHTTPRequestHandler):
    state: GatewayState = None          # set by serve()
    server_version = "recallite-gateway"

    # -- plumbing ---------------------------------------------------------

    def log_message(self, fmt, *args):
        log.info("%s " + fmt, self.address_string(), *args)

    def _json(self, code: int, obj: dict):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _error(self, code: int, message: str):
        self._json(code, {"error": {"message": message, "type": "recallite"}})

    def _bearer(self) -> str:
        auth = self.headers.get("Authorization", "")
        return auth[7:] if auth.startswith("Bearer ") else ""

    def _read_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length > MAX_BODY:
            raise PrivacyError("Request body too large; refused.")
        return json.loads(self.rfile.read(length).decode("utf-8"))

    # -- routes -----------------------------------------------------------

    def do_GET(self):
        if self.path == "/health":
            return self._json(200, {"status": "ok", "mode": self.state.mode})
        if self.state.gateway_tenant(self._bearer()) is None:
            return self._error(401, "Missing or invalid API key.")
        if self.path == "/v1/models":
            try:
                req = urllib.request.Request(self.state.upstream + "/models")
                with urllib.request.urlopen(req, timeout=20) as resp:
                    return self._json(200, json.loads(resp.read()))
            except Exception:
                return self._error(502, "Upstream unreachable.")
        return self._error(404, "Unknown endpoint.")

    def do_POST(self):
        try:
            body = self._read_body()
        except PrivacyError as e:
            return self._error(413, str(e))
        except Exception:
            return self._error(400, "Invalid JSON body.")

        if self.path == "/v1/privacy/restore":
            return self._restore(body)          # restore credential only

        tenant = self.state.gateway_tenant(self._bearer())
        if tenant is None:
            return self._error(401, "Missing or invalid API key.")
        if self.path == "/v1/chat/completions":
            return self._chat(body, tenant)
        if self.path == "/v1/privacy/check":
            return self._check(body)
        return self._error(404, "Unknown endpoint.")

    # -- privacy utility endpoints ---------------------------------------

    def _check(self, body: dict):
        try:
            found = detect_sensitive(str(body.get("text", "")),
                                     name_detector=self.state.shield
                                     .name_detector,
                                     strict=self.state.shield.strict)
        except PrivacyError as e:
            return self._error(400, str(e))
        return self._json(200, {
            "categories": {k: len(v) for k, v in found.items()},
            "would_block": sorted(set(found) & BLOCKING),
            "never_restored": sorted(set(found) & NEVER_RESTORE)})

    def _restore(self, body: dict):
        """Trusted restoration services only: distinct credential, session
        ownership, per-key tenant scope, per-key category allowlist,
        destination allowlist. Chat keys are refused. Model output never
        reaches this path on its own — a human-built application calls it."""
        ident = self.state.restore_identity(self._bearer())
        if ident is None:
            denied = "restore" if self.state.gateway_tenant(self._bearer()) \
                else "missing"
            log.warning("restore denied (%s credential)", denied)
            return self._error(403, "Restoration requires a restore "
                                    "credential; chat keys cannot restore.")
        sid = str(body.get("session", ""))
        with self.state.lock:
            s = self.state.sessions.get(sid)
        if s is None or s.psession.expired():
            return self._error(404, "Unknown or expired privacy session.")
        key_tenant = ident.get("tenant")
        if key_tenant and key_tenant != s.tenant:
            log.warning("restore denied: tenant scope mismatch")
            return self._error(403, "This restore credential is not scoped "
                                    "to the session's tenant.")
        destination = str(body.get("destination", "app"))
        allowed_dest = {d.strip() for d in
                        ident.get("destinations",
                                  ",".join(self.state.restore_destinations)
                                  ).split(",")}
        if destination not in allowed_dest \
                or destination not in self.state.restore_destinations:
            return self._error(403, f"Destination '{destination}' is not "
                                    f"authorized for restoration.")
        want = {str(c).lower() for c in body.get("categories", [])} \
            or self.state.restore_allow
        key_cats = ident.get("categories")
        if key_cats:
            want &= {c.strip().lower() for c in key_cats.split(",")}
        allowed = want & self.state.restore_allow
        try:
            with s.lock:
                text, report = self.state.shield.restore(
                    str(body.get("text", "")), s.psession,
                    allowed_categories=allowed)
        except PrivacyError as e:
            return self._error(410, str(e))
        log.info("restore tenant=%s dest=%s allowed=%s restored=%d "
                 "refused=%d", s.tenant, destination, sorted(allowed),
                 report["restored"], report["refused_or_unknown"])
        return self._json(200, {"text": text, **report,
                                "allowed_categories": sorted(allowed),
                                "destination": destination})

    # -- schema-aware sanitization ----------------------------------------

    def _san(self, text: str, s: _Session, counts: dict) -> str:
        with s.lock:
            clean, rep = self.state.shield.sanitize(text,
                                                    session=s.psession)
        for k, v in rep["categories"].items():
            counts[k] = counts.get(k, 0) + v
        return clean

    def _san_tree(self, obj, s: _Session, counts: dict):
        """Recursively sanitize every string value in app-authored
        structures (tool definitions, schemas, arguments)."""
        if isinstance(obj, str):
            return self._san(obj, s, counts)
        if isinstance(obj, list):
            return [self._san_tree(x, s, counts) for x in obj]
        if isinstance(obj, dict):
            return {k: self._san_tree(v, s, counts) for k, v in obj.items()}
        return obj

    def _clean_message(self, m: dict, s: _Session, counts: dict) -> dict:
        unknown = set(m) - ALLOWED_MSG_FIELDS
        if unknown:
            raise PrivacyError(
                f"Unsupported message field(s) rejected: "
                f"{', '.join(sorted(unknown))}.")
        role = m.get("role")
        if role not in ALLOWED_ROLES:
            raise PrivacyError(f"Unsupported message role: {role!r}.")
        out = {"role": role}
        content = m.get("content", "")
        if isinstance(content, list):
            texts = []
            for part in content:
                if not (isinstance(part, dict)
                        and part.get("type") == "text"
                        and set(part) <= {"type", "text"}):
                    raise PrivacyError(
                        "Uninspectable content part blocked (only "
                        "{'type': 'text'} parts are accepted).")
                texts.append(str(part.get("text", "")))
            out["content"] = self._san("\n".join(texts), s, counts)
        elif isinstance(content, str) or content is None:
            out["content"] = self._san(content or "", s, counts)
        else:
            raise PrivacyError("Uninspectable content blocked.")
        if "name" in m:
            out["name"] = self._san(str(m["name"]), s, counts)
        if "tool_call_id" in m:
            if not isinstance(m["tool_call_id"], str):
                raise PrivacyError("tool_call_id must be a string.")
            out["tool_call_id"] = m["tool_call_id"]
        if "tool_calls" in m:
            out["tool_calls"] = [self._clean_tool_call(tc, s, counts)
                                 for tc in (m["tool_calls"] or [])]
        return out

    def _clean_tool_call(self, tc, s: _Session, counts: dict) -> dict:
        if not isinstance(tc, dict) or \
                set(tc) - {"id", "type", "function", "index"}:
            raise PrivacyError("Unsupported tool_call shape rejected.")
        fn = tc.get("function", {})
        if tc.get("type") != "function" or \
                set(fn) - {"name", "arguments"}:
            raise PrivacyError("Unsupported tool_call shape rejected.")
        return {"id": str(tc.get("id", "")), "type": "function",
                "function": {
                    "name": str(fn.get("name", "")),
                    "arguments": self._san(str(fn.get("arguments", "")),
                                           s, counts)}}

    # -- structured-response DLP -----------------------------------------

    def _dlp(self, text: str, redacted: dict) -> str:
        clean, rep = self.state.shield.scan_output(text)
        for k, v in rep["redacted"].items():
            redacted[k] = redacted.get(k, 0) + v
        return clean

    def _scrub_response(self, data: dict, report: dict) -> dict:
        redacted: dict = {}
        stripped: list = []
        for choice in data.get("choices", []):
            if "logprobs" in choice and choice["logprobs"] is not None:
                choice["logprobs"] = None       # token text pre-dates DLP
                stripped.append("logprobs")
            msg = choice.get("message")
            if not isinstance(msg, dict):
                continue
            for f in [f for f in list(msg) if f not in RESP_MSG_FIELDS]:
                del msg[f]
                stripped.append(f"message.{f}")
            if msg.get("content"):
                msg["content"] = self._dlp(msg["content"], redacted)
            if msg.get("refusal"):
                msg["refusal"] = self._dlp(msg["refusal"], redacted)
            for tc in (msg.get("tool_calls") or []):
                fn = tc.get("function") if isinstance(tc, dict) else None
                if isinstance(fn, dict) and "arguments" in fn:
                    fn["arguments"] = self._dlp(str(fn["arguments"]),
                                                redacted)
            fc = msg.get("function_call")
            if isinstance(fc, dict) and "arguments" in fc:
                fc["arguments"] = self._dlp(str(fc["arguments"]), redacted)
        known_top = {"id", "object", "created", "model", "usage", "choices",
                     "system_fingerprint", "service_tier"}
        for f in [f for f in list(data) if f not in known_top]:
            del data[f]
            stripped.append(f)
        if redacted:
            report["output_redacted"] = redacted
        if stripped:
            report["stripped_response_fields"] = sorted(set(stripped))
        return data

    # -- the sanitizing proxy --------------------------------------------

    def _chat(self, body: dict, tenant: str):
        unknown = set(body) - ALLOWED_TOP
        if unknown:
            return self._error(400, f"Unsupported field(s) rejected: "
                                    f"{', '.join(sorted(unknown))}.")
        messages = body.get("messages")
        if not isinstance(messages, list) or not messages:
            return self._error(400, "messages must be a non-empty list.")

        sid = body.get("recallite_session")
        if sid is not None:
            s = self.state.get_session(str(sid), tenant)
            if s is None:
                log.warning("session refused tenant=%s", tenant)
                return self._error(403, "Unknown, expired, or foreign "
                                        "privacy session.")
        else:
            sid = self.state.mint_session(tenant)
            s = self.state.get_session(sid, tenant)

        counts: dict = {}
        try:
            clean_msgs = [self._clean_message(m, s, counts)
                          for m in messages]
            upstream_body = {}
            for k in FORWARD_TOP:
                if k not in body:
                    continue
                if k in ("tools", "tool_choice", "response_format"):
                    upstream_body[k] = self._san_tree(body[k], s, counts)
                else:
                    upstream_body[k] = body[k]
        except PrivacyError as e:
            log.warning("blocked request tenant=%s reason=%s", tenant, e)
            return self._error(400, str(e))

        upstream_body["messages"] = clean_msgs
        upstream_body["stream"] = False      # scan complete responses
        try:
            req = urllib.request.Request(
                self.state.upstream + "/chat/completions",
                data=json.dumps(upstream_body).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=300) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception:
            return self._error(502, "Upstream model unreachable.")

        report = {"sanitized": counts, "session": sid,
                  "mode": self.state.mode}
        data = self._scrub_response(data, report)
        data["recallite"] = report
        log.info("chat tenant=%s session=%s sanitized=%s", tenant,
                 sid[:8], counts)

        if body.get("stream"):
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            chunk = {"id": data.get("id", "recallite"),
                     "object": "chat.completion.chunk",
                     "model": data.get("model"),
                     "choices": [{"index": 0, "delta":
                                  {"content": (c.get("message") or {})
                                   .get("content", "")},
                                  "finish_reason": "stop"}
                                 for c in data.get("choices", [])[:1]],
                     "recallite": report}
            self.wfile.write(b"data: " + json.dumps(chunk).encode() + b"\n\n")
            self.wfile.write(b"data: [DONE]\n\n")
            return
        self._json(200, data)


def serve(upstream: str, mode: str = "tokenize", port: int = 8787,
          restore: str = "", key_file: str | None = None,
          session_ttl: int = 900, ner: str = "auto",
          restore_key_file: str | None = None,
          restore_destinations: str = "app") -> ThreadingHTTPServer:
    """Build and return the server (caller runs serve_forever)."""
    gw_key = load_or_create_key(key_file, DEFAULT_KEY_FILE, "gateway")
    rs_key = load_or_create_key(restore_key_file, DEFAULT_RESTORE_KEY_FILE,
                                "restore")
    gateway_keys = _parse_key_file(
        Path(key_file or DEFAULT_KEY_FILE).expanduser()) or {gw_key: {}}
    restore_keys = _parse_key_file(
        Path(restore_key_file or DEFAULT_RESTORE_KEY_FILE).expanduser()) \
        or {rs_key: {}}
    overlap = set(gateway_keys) & set(restore_keys)
    if overlap:
        raise ValueError("A key may not be both a gateway key and a "
                         "restore key; use distinct credentials.")
    restore_allow = {c.strip() for c in restore.split(",") if c.strip()}
    GatewayHandler.state = GatewayState(
        upstream, mode, gateway_keys, restore_keys, restore_allow,
        {d.strip() for d in restore_destinations.split(",") if d.strip()},
        session_ttl, ner=ner)
    return ThreadingHTTPServer(("127.0.0.1", port), GatewayHandler)


def main(argv=None) -> int:
    import argparse
    p = argparse.ArgumentParser(prog="recallite gateway")
    p.add_argument("--upstream", required=True)
    p.add_argument("--mode", choices=["redact", "tokenize"],
                   default="tokenize")
    p.add_argument("--port", type=int, default=8787)
    p.add_argument("--restore", default="",
                   help="categories trusted restoration services may "
                        "restore (SSN/PAN/CVV can never be listed)")
    p.add_argument("--key-file", default=None)
    p.add_argument("--restore-key-file", default=None)
    p.add_argument("--restore-destinations", default="app")
    p.add_argument("--ner", choices=["auto", "off", "strict"],
                   default="auto",
                   help="name detection: auto (use if installed), off, or "
                        "strict (REQUIRED — refuse all content without it)")
    p.add_argument("--session-ttl", type=int, default=900)
    a = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(name)s %(message)s")
    try:
        httpd = serve(a.upstream, a.mode, a.port, a.restore, a.key_file,
                      a.session_ttl, ner=a.ner,
                      restore_key_file=a.restore_key_file,
                      restore_destinations=a.restore_destinations)
    except (PrivacyError, ValueError) as e:
        print(f"[gateway] refusing to start: {e}")
        return 1
    print(f"[gateway] mode={a.mode} ner={a.ner} upstream={a.upstream} "
          f"listening on http://127.0.0.1:{a.port} (loopback only)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
