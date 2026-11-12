"""
recallite.cli — run a memory chat from the terminal, no code needed.

    recallite chat --backend ollama --model llama3.2
    recallite chat --backend openai --model llama-3.2 --url http://localhost:8000/v1
    recallite chat --backend hf --model Qwen/Qwen2.5-1.5B-Instruct
    recallite chat --secure --pii redact
"""

from __future__ import annotations

import argparse

from .store import MemoryStore
from .agent import MemoryAgent
from .guardrails import Guardrails
from .adapters import OllamaBackend, OpenAICompatBackend, HuggingFaceBackend


def main() -> None:
    p = argparse.ArgumentParser(prog="recallite",
                                description="Persistent memory for any LLM.")
    from . import __version__
    p.add_argument("--version", action="version",
                   version=f"recallite {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    chat = sub.add_parser("chat", help="interactive memory chat")
    chat.add_argument("--backend", choices=["ollama", "openai", "hf", "none"],
                      default="ollama")
    chat.add_argument("--model", default="llama3.2")
    chat.add_argument("--url", default=None,
                      help="server URL (ollama host or openai base_url)")
    chat.add_argument("--db", default="recallite.db")
    chat.add_argument("--user", default="default")
    chat.add_argument("--secure", action="store_true",
                      help="password-protect memory")
    chat.add_argument("--pii", choices=["allow", "warn", "redact", "block"],
                      default="warn", help="PII guardrail mode")
    chat.add_argument("--no-stream", action="store_true")
    chat.add_argument("--encrypted", action="store_true",
                      help="encrypt memories at rest (passphrase from "
                           "RECALLITE_PASSPHRASE, --passphrase-file, or a "
                           "hidden prompt — never from argv)")
    chat.add_argument("--passphrase-file", metavar="FILE", default=None)

    bench = sub.add_parser("bench", help="run the reproducible memory benchmark")
    bench.add_argument("--full", action="store_true",
                       help="larger corpus + percentiles (slower)")
    bench.add_argument("--json", metavar="FILE",
                       help="also write machine-readable results")
    bench.add_argument("--embedder", choices=["toy", "st", "ollama"],
                       default="toy")
    bench.add_argument("--compare", metavar="FILE")

    gw = sub.add_parser("gateway",
                        help="privacy gateway: sanitize prompts before any model")
    gw.add_argument("--upstream", required=True)
    gw.add_argument("--mode", choices=["redact", "tokenize"],
                    default="tokenize")
    gw.add_argument("--port", type=int, default=8787)
    gw.add_argument("--restore", default="")
    gw.add_argument("--key-file", default=None)
    gw.add_argument("--restore-key-file", default=None)
    gw.add_argument("--restore-destinations", default="app")
    gw.add_argument("--ner", choices=["auto", "off", "strict"],
                    default="auto")
    gw.add_argument("--session-ttl", type=int, default=900)

    mcp_p = sub.add_parser("mcp", help="MCP server: sanitized memory tools "
                                       "(no restore tool, by design)")
    mcp_p.add_argument("--db", default="recallite.db")
    mcp_p.add_argument("--user", default="default")
    mcp_p.add_argument("--transport", choices=["stdio", "http"],
                       default="stdio")
    mcp_p.add_argument("--port", type=int, default=8765)
    mcp_p.add_argument("--privacy", choices=["redact", "off"],
                       default="redact")
    mcp_p.add_argument("--ner", choices=["auto", "off", "strict"],
                       default="auto")
    mcp_p.add_argument("--key-file", default=None)

    uat = sub.add_parser("uat", help="run release UAT prompts against a REAL model")
    uat.add_argument("--backend", choices=["ollama", "openai"], default="ollama")
    uat.add_argument("--model", default="llama3.2")
    uat.add_argument("--url", default=None)
    uat.add_argument("--prompts", metavar="FILE")
    uat.add_argument("--password-file", metavar="FILE")
    uat.add_argument("--report", metavar="FILE")

    args = p.parse_args()

    if args.cmd == "mcp":
        from .mcp_server import main as mcp_main
        argv = ["--db", args.db, "--user", args.user,
                "--transport", args.transport, "--port", str(args.port),
                "--privacy", args.privacy, "--ner", args.ner]
        if args.key_file:
            argv += ["--key-file", args.key_file]
        raise SystemExit(mcp_main(argv))

    if args.cmd == "gateway":
        from .gateway import main as gw_main
        argv = ["--upstream", args.upstream, "--mode", args.mode,
                "--port", str(args.port), "--restore", args.restore,
                "--session-ttl", str(args.session_ttl),
                "--ner", args.ner,
                "--restore-destinations", args.restore_destinations]
        if args.key_file:
            argv += ["--key-file", args.key_file]
        if args.restore_key_file:
            argv += ["--restore-key-file", args.restore_key_file]
        raise SystemExit(gw_main(argv))

    if args.cmd == "uat":
        from .uat import main as uat_main, DEFAULT_PASSWORD_FILE
        argv = ["--backend", args.backend, "--model", args.model,
                "--password-file", args.password_file or DEFAULT_PASSWORD_FILE]
        if args.url:
            argv += ["--url", args.url]
        if args.prompts:
            argv += ["--prompts", args.prompts]
        if args.report:
            argv += ["--report", args.report]
        raise SystemExit(uat_main(argv))

    if args.cmd == "bench":
        from .bench import main as bench_main
        argv = []
        if args.full:
            argv.append("--full")
        if args.json:
            argv += ["--json", args.json]
        if args.compare:
            argv += ["--compare", args.compare]
        argv += ["--embedder", args.embedder]
        raise SystemExit(bench_main(argv))

    passphrase = None
    if args.encrypted:
        import os
        passphrase = (os.environ.get("RECALLITE_PASSPHRASE")
                      or os.environ.get("MEMLAYER_PASSPHRASE"))
        if not passphrase and args.passphrase_file:
            from pathlib import Path as _P
            passphrase = _P(args.passphrase_file).expanduser() \
                .read_text(encoding="utf-8").strip()
        if not passphrase:
            import getpass
            passphrase = getpass.getpass("Encryption passphrase (hidden): ")

    guard = Guardrails(pii_mode=args.pii)
    store = MemoryStore(args.db, user_id=args.user, secure=args.secure,
                        guardrails=guard,
                        encryption_passphrase=passphrase)

    backend = None
    if args.backend == "ollama":
        backend = OllamaBackend(args.model,
                                host=args.url or "http://localhost:11434")
    elif args.backend == "openai":
        backend = OpenAICompatBackend(
            args.model, base_url=args.url or "http://localhost:8000/v1")
    elif args.backend == "hf":
        backend = HuggingFaceBackend(args.model)

    MemoryAgent(store, backend).repl(stream=not args.no_stream)


if __name__ == "__main__":
    main()
