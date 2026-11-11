"""
recallite.agent — slash commands + retrieval + history + any backend.
"""

from __future__ import annotations

import re
import sys
from collections import deque
from pathlib import Path
from typing import Optional

from .store import MemoryStore, parse_duration
from .adapters import BaseBackend

HELP = (
    "Commands:\n"
    "  /save <keyword> <fact>        — remember a fact  (quote multi-word keywords)\n"
    "  /save --expires 30d <kw> <f>  — fact that auto-deletes (m/h/d/w)\n"
    "  /save! ...                    — force-save even if a similar memory exists\n"
    "  /replace <id> <kw> <fact>     — overwrite an old memory\n"
    "  /undo                         — delete the last saved memory\n"
    "  /search [--type t] [--keyword k] [--source s] <query>\n"
    "                                — search with filters + explanations\n"
    "  /memories                     — list everything saved\n"
    "  /forget <id>   /clear         — delete one / all\n"
    "  /stats                        — memory statistics\n"
    "  /export [file] /import <file> — backup / restore JSON\n"
    "  /block <term> /unblock <term>  — manage prohibited terms\n"
    "  /history <keyword>            — see current + superseded versions\n"
    "  /auto on|off                  — suggest memories from conversation\n"
    "  /save --type <t> --importance <0-1> ...  — typed facts\n"
    "       types: semantic | preference | episodic | procedural\n"
    "  /consolidate [apply]          — merge near-duplicate memories\n"
    "  /retention <days>|off         — auto-delete old history\n"
    "  /compact                      — rewrite db; purge deleted traces\n"
    "  /task add <name> <kw> <url>   — define a URL-fetch task\n"
    "  /task run|list|remove ...     — run tasks; re-runs supersede old data\n"
    "  /blocked                      — list prohibited terms\n"
    "  /profile <name>               — switch memory profile\n"
    "  /enable [password]  /lock     — secure mode unlock / lock\n"
    "  /passwd [current new]         — change the password\n"
    "  /help                         — this help"
)

LOCKED_MSG = ("Memory is locked (secure mode). "
              "Unlock with: /enable <password>")


def _split_keyword(payload: str) -> tuple[str, str]:
    """('age', 'Ali is 36') | quoted: ('favorite food', 'Ali loves biryani')"""
    payload = payload.strip()
    if not payload:
        return "", ""
    if payload[0] in ('"', "'"):
        end = payload.find(payload[0], 1)
        if end == -1:
            return "", ""
        return payload[1:end].strip(), payload[end + 1:].strip()
    parts = payload.split(maxsplit=1)
    return (parts[0], parts[1]) if len(parts) == 2 else ("", "")


class MemoryAgent:
    def __init__(self, store: MemoryStore, backend: Optional[BaseBackend] = None,
                 system_prompt: str = "You are a helpful assistant.",
                 top_k: int = 5, history_turns: int = 6,
                 max_context_tokens: Optional[int] = 600):
        self.store = store
        self.backend = backend
        self.system_prompt = system_prompt
        self.top_k = top_k
        self.max_context_tokens = max_context_tokens
        self.history: deque = deque(maxlen=history_turns * 2)
        self._last_saved_id: Optional[str] = None
        self.auto_extract = False
        self._tasks = None

    # ------------------------------------------------------------------
    # save helper (expiry flag, contradiction check, force)
    # ------------------------------------------------------------------

    def _do_save(self, payload: str, force: bool,
                 supersedes: str = None) -> str:
        expires_in = None
        memory_type = None
        importance = None
        # leading flags in any order: --expires 30d --type preference
        # --importance 0.8
        while True:
            m = re.match(r"--(expires|type|importance)\s+(\S+)\s+(.*)",
                         payload, re.DOTALL)
            if not m:
                break
            flag, value, payload = m.group(1), m.group(2), m.group(3)
            if flag == "expires":
                expires_in = parse_duration(value)
                if expires_in is None:
                    return "Bad duration. Use e.g. 45m, 12h, 30d, 2w."
            elif flag == "type":
                from .store import MEMORY_TYPES
                if value.lower() not in MEMORY_TYPES:
                    return (f"Unknown type {value!r}. Types: "
                            + ", ".join(MEMORY_TYPES))
                memory_type = value.lower()
            else:
                try:
                    importance = float(value)
                except ValueError:
                    return "Importance must be a number between 0 and 1."

        keyword, fact = _split_keyword(payload)
        if not keyword or not fact:
            return ("Usage: /save <keyword> <fact>\n"
                    'e.g.  /save age Ali is 36   |   /save "favorite food" ...')

        if not force:
            dup = self.store.find_similar(keyword, fact)
            if dup:
                return (f"A similar memory exists [{dup['id']}] "
                        f"({dup['keyword']}): \"{dup['text']}\"\n"
                        f"  /replace {dup['id']} {keyword} {fact}   — supersede it (kept as history)\n"
                        f"  /save! {keyword} {fact}                — keep both active")
        try:
            rec = self.store.save(fact, keyword=keyword, expires_in=expires_in,
                                  supersedes=supersedes,
                                  memory_type=memory_type,
                                  importance=importance)
        except (ValueError, PermissionError) as e:
            return str(e)
        self._last_saved_id = rec["id"]
        extra = f"  [{'; '.join(rec['warnings'])}]" if rec.get("warnings") else ""
        exp = f" (expires {rec['expires_at']})" if rec.get("expires_at") else ""
        sup = f" — superseded [{rec['supersedes']}]" if rec.get("supersedes") else ""
        return f'Saved [{rec["id"]}] ({rec["keyword"]}): "{rec["text"]}"{exp}{sup}{extra}'

    # ------------------------------------------------------------------

    MEMORY_CMDS = frozenset({
        "/save", "/save!", "/replace", "/undo", "/search", "/memories",
        "/list", "/forget", "/clear", "/stats", "/export", "/import",
        "/block", "/unblock", "/blocked", "/history", "/task",
        "/consolidate", "/retention", "/compact"})
    ALL_CMDS = MEMORY_CMDS | {"/enable", "/passwd", "/lock", "/profile",
                              "/auto", "/help"}

    def handle_command(self, text: str) -> Optional[str]:
        t = text.strip()
        if not t.startswith("/"):
            return None
        # exact first-token matching: "/clearance levels" is NOT /clear
        cmd, _, rest = t.partition(" ")
        cmd = cmd.lower()
        rest = rest.strip()
        if cmd not in self.ALL_CMDS:
            return (f"Unknown command {cmd}. Type /help for the list. "
                    f"(Messages starting with / are treated as commands.)")
        sec = self.store.security

        if cmd == "/enable":
            password = rest
            if not password and sys.stdin.isatty():
                import getpass
                password = getpass.getpass("Password (hidden): ")
            if not password:
                return "Usage: /enable <password>"
            return sec.enable(password)

        if cmd == "/passwd":
            parts = rest.split()
            if len(parts) == 2:
                old, new = parts
            elif not parts and sys.stdin.isatty():
                import getpass
                old = getpass.getpass("Current password (hidden): ")
                new = getpass.getpass("New password (hidden): ")
                confirm = getpass.getpass("Repeat new password (hidden): ")
                if new != confirm:
                    return "New passwords do not match. Password unchanged."
            else:
                return ("Usage: /passwd <current> <new>\n"
                        "(or just /passwd in a terminal for hidden prompts)")
            return sec.change_password(old, new)

        if cmd == "/lock":
            return sec.lock()

        if cmd == "/profile":
            if not rest:
                return f"Current profile: {self.store.user_id}"
            self.store.switch_user(rest)
            self.history.clear()
            new_sec = self.store.security
            state = " (locked)" if (new_sec.secure and
                                    not new_sec.check()) else ""
            return f"Switched to profile '{rest}'{state}."

        if cmd == "/auto":
            arg = rest.lower()
            if arg == "on":
                self.auto_extract = True
                return ("Auto-extraction ON: after each reply I will suggest "
                        "facts worth saving. Nothing is saved without you.")
            if arg == "off":
                self.auto_extract = False
                return "Auto-extraction OFF."
            return (f"Auto-extraction is "
                    f"{'ON' if self.auto_extract else 'OFF'}. Use /auto on|off.")

        if cmd == "/help":
            return HELP

        # every remaining command touches memory -> lock check
        if not sec.check():
            return LOCKED_MSG

        if cmd == "/task":
            from .tasks import TaskManager
            if self._tasks is None:
                self._tasks = TaskManager(self.store)
            parts = rest.split(maxsplit=1)
            sub = parts[0].lower() if parts else ""
            arg = parts[1] if len(parts) > 1 else ""
            if sub == "add":
                p = arg.split(maxsplit=2)
                if len(p) < 3:
                    return ("Usage: /task add <name> <keyword> <url>\n"
                            "e.g.  /task add news headlines https://example.com")
                return self._tasks.add(p[0], p[1], p[2])
            if sub == "run":
                if not arg:
                    return "Usage: /task run <name>"
                return self._tasks.run(arg)
            if sub == "list":
                return self._tasks.list()
            if sub == "remove":
                if not arg:
                    return "Usage: /task remove <name>"
                return self._tasks.remove(arg)
            return ("Usage: /task add <name> <keyword> <url> | "
                    "/task run <name> | /task list | /task remove <name>")

        if cmd == "/consolidate":
            apply = rest.strip().lower() == "apply"
            props = self.store.consolidate(apply=apply)
            if not props:
                return "No near-duplicate memories found."
            lines = []
            for p in props:
                lines.append(f'({p["keyword"]}) keep [{p["keep"]["id"]}] '
                             f'"{p["keep"]["text"][:60]}"')
                for m in p["supersede"]:
                    lines.append(f'    supersede [{m["id"]}] '
                                 f'"{m["text"][:60]}"')
            head = ("Consolidated:" if apply else
                    "Proposed consolidation (run `/consolidate apply` "
                    "to execute):")
            return head + "\n" + "\n".join(lines)

        if cmd == "/retention":
            arg = rest.strip().lower()
            if not arg:
                d = self.store.get_retention()
                return (f"Retention: superseded history deleted after "
                        f"{d} days." if d else
                        "Retention: off (history kept forever). "
                        "Set with /retention <days>.")
            if arg == "off":
                self.store.set_retention(None)
                return "Retention off — history is kept forever."
            if not arg.isdigit():
                return "Usage: /retention <days> | off"
            self.store.set_retention(int(arg))
            return (f"Retention set: superseded history older than {arg} "
                    f"days is deleted automatically. Active memories are "
                    f"never auto-deleted.")

        if cmd == "/compact":
            freed = self.store.compact()
            return (f"Compacted: database rewritten, {freed/1024:.1f} KB "
                    f"freed. Deleted rows leave no traces in the file.")

        if cmd == "/save!":
            return self._do_save(rest, force=True)
        if cmd == "/save":
            return self._do_save(rest, force=False)

        if cmd == "/replace":
            parts = rest.split(maxsplit=1)
            if len(parts) < 2:
                return "Usage: /replace <id> <keyword> <fact>"
            return self._do_save(parts[1], force=True, supersedes=parts[0])

        if cmd == "/history":
            kw = rest.strip('"').strip("'")
            if not kw:
                return "Usage: /history <keyword>"
            chain = self.store.history(kw)
            if not chain:
                return f'No memories under keyword "{kw}".'
            lines = []
            for m in chain:
                mark = "ACTIVE " if m["status"] == "active" else "old    "
                lines.append(f'{mark}[{m["id"]}] {m["text"]}  '
                             f'({m["created_at"]}, {m["source"]}, '
                             f'conf {m["confidence"]:.1f})')
            return f'History for "{kw}":\n' + "\n".join(lines)

        if cmd == "/undo":
            if not self._last_saved_id:
                return "Nothing to undo."
            ok = self.store.forget(self._last_saved_id)
            mid, self._last_saved_id = self._last_saved_id, None
            return f"Removed [{mid}]." if ok else "Already removed."

        if cmd == "/search":
            filters = {}
            while True:
                m2 = re.match(r"--(type|keyword|source)\s+(\S+)(?:\s+(.*))?$",
                              rest, re.DOTALL)
                if not m2:
                    break
                flag, value = m2.group(1), m2.group(2)
                rest = m2.group(3) or ""
                filters["memory_type" if flag == "type" else flag] = value
            if not rest.strip():
                return ("Usage: /search [--type t] [--keyword k] "
                        "[--source s] <query>")
            hits = self.store.search(rest.strip(), top_k=5,
                                     filters=filters or None, explain=True)
            if not hits:
                return "No matching memories."
            lines = []
            for m in hits:
                ex = m.get("explain", {})
                sig = []
                if ex.get("lexical_rank"):
                    sig.append(f"lex#{ex['lexical_rank']}")
                if ex.get("semantic_rank"):
                    sig.append(f"sem#{ex['semantic_rank']}")
                lines.append(
                    f"[{m['id']}] ({m['keyword']}) <{m['memory_type']}> "
                    f"{m['text']}\n"
                    f"      conf {m['confidence']:.1f} · imp "
                    f"{m['importance']:.1f} · {m['source']} · "
                    f"{' '.join(sig) or 'recency'}")
            return "Matches:\n" + "\n".join(lines)

        if cmd in ("/memories", "/list"):
            mems = self.store.all()
            if not mems:
                return "No memories saved yet."
            return "Saved memories:\n" + "\n".join(
                f"[{m['id']}] ({m['keyword']}) <{m['memory_type']}> "
                f"{m['text']}  ({m['created_at']})"
                for m in mems)

        if cmd == "/forget":
            if not rest:
                return "Usage: /forget <memory id>"
            return (f"Forgot memory {rest}." if self.store.forget(rest)
                    else f"No memory found with id {rest}.")

        if cmd == "/clear":
            return f"Cleared {self.store.clear()} memories."

        if cmd == "/stats":
            s = self.store.stats()
            kws = ", ".join(f"{k}: {v}" for k, v in
                            sorted(s["by_keyword"].items())) or "-"
            return (f"Profile: {self.store.user_id}\n"
                    f"Memories: {s['count']}\nBy keyword: {kws}\n"
                    f"DB size: {s['db_bytes']/1024:.1f} KB\n"
                    f"Oldest: {s['oldest']}  Newest: {s['newest']}")

        if cmd == "/export":
            fname = rest or "recallite_export.json"
            Path(fname).write_text(self.store.export_json(), encoding="utf-8")
            return f"Exported {self.store.count()} memories to {fname}"

        if cmd == "/import":
            if not rest or not Path(rest).exists():
                return "Usage: /import <file.json>  (file must exist)"
            try:
                n = self.store.import_json(
                    Path(rest).read_text(encoding="utf-8"))
            except ValueError as e:
                return f"Import rejected: {e}"
            rep = getattr(self.store, "last_import_report", {})
            extra = ""
            if rep.get("skipped"):
                extra = (f" ({rep['skipped']} record(s) skipped by "
                         f"guardrails: {'; '.join(rep['reasons'])})")
            return f"Imported {n} memories.{extra}"

        if cmd == "/blocked":
            terms = self.store.list_blocked()
            return ("Prohibited terms: " + ", ".join(terms)) if terms \
                else "No prohibited terms set. Add one with /block <term>."

        if cmd == "/block":
            if not rest:
                return "Usage: /block <term>"
            self.store.add_blocked(rest)
            return (f'Added prohibited term "{rest.lower()}". '
                    f"Saves containing it will be refused.")

        if cmd == "/unblock":
            if not rest:
                return "Usage: /unblock <term>"
            return (f'Removed "{rest.lower()}" from prohibited terms.'
                    if self.store.remove_blocked(rest)
                    else f'"{rest.lower()}" was not in the prohibited list.')

        return None

    EXTRACT_PROMPT = (
        "Review the user's last message and extract up to 3 NEW lasting "
        "facts about the user (identity, preference, plan, relationship, "
        "work, how they do things). Reply ONLY with JSON matching this "
        "schema:\n"
        '{"facts": [{"type": "semantic|preference|episodic|procedural", '
        '"keyword": "one or two words", '
        '"fact": "the fact, third person", '
        '"importance": 0.0}]}\n'
        'Importance: 0.0-1.0, how lastingly useful the fact is. '
        'If nothing is worth remembering long-term reply ONLY: '
        '{"facts": []}')

    def _suggest_memory(self, user_input: str) -> str:
        """Ask the backend for structured memory candidates (JSON schema,
        up to 3 facts). Returns suggestion lines or empty string. Never
        saves anything itself — the user confirms each /save."""
        if not (self.auto_extract and self.backend):
            return ""
        try:
            raw = self.backend.chat(self.EXTRACT_PROMPT, user_input).strip()
            if raw.upper().startswith("NONE"):
                return ""
            import json as _json
            from .store import MEMORY_TYPES
            start, end = raw.find("{"), raw.rfind("}")
            if start == -1 or end == -1:
                return ""
            data = _json.loads(raw[start:end + 1])
            facts = data.get("facts")
            if facts is None and data.get("fact"):   # legacy single-fact
                facts = [data]
            if not isinstance(facts, list):
                return ""
            lines = []
            for cand in facts[:3]:
                if not isinstance(cand, dict):
                    continue
                kw = str(cand.get("keyword", "")).strip()
                fact = str(cand.get("fact", "")).strip()
                if not kw or not fact:
                    continue
                if self.store.find_similar(kw, fact, threshold=0.5):
                    continue              # already known (incl. paraphrases)
                mtype = str(cand.get("type", "")).lower()
                flags = ""
                if mtype in MEMORY_TYPES and mtype != "semantic":
                    flags += f"--type {mtype} "
                try:
                    imp = float(cand.get("importance"))
                    if 0.0 <= imp <= 1.0:
                        flags += f"--importance {imp:.1f} "
                except (TypeError, ValueError):
                    pass
                quoted = f'"{kw}"' if " " in kw else kw
                lines.append(f"/save {flags}{quoted} {fact}")
            if not lines:
                return ""
            return ("\n\n[memory suggestions] Worth remembering? Type any "
                    "of:\n  " + "\n  ".join(lines))
        except Exception:
            return ""         # extraction must never break the chat

    def _system_with_memory(self, user_input: str) -> str:
        ctx = self.store.build_context(
            query=user_input, top_k=self.top_k,
            max_context_tokens=self.max_context_tokens)
        return self.system_prompt + ("\n\n" + ctx if ctx else "")

    def ask(self, user_input: str) -> str:
        cmd = self.handle_command(user_input)
        if cmd is not None:
            return cmd
        system = self._system_with_memory(user_input)
        if self.backend is None:
            return f"(no backend)\n--- system prompt ---\n{system}"
        reply = self.backend.chat(system, user_input, list(self.history))
        self.history.append({"role": "user", "content": user_input})
        self.history.append({"role": "assistant", "content": reply})
        return reply + self._suggest_memory(user_input)

    def ask_stream(self, user_input: str):
        """Yields chunks. Commands yield a single chunk."""
        cmd = self.handle_command(user_input)
        if cmd is not None:
            yield cmd
            return
        system = self._system_with_memory(user_input)
        if self.backend is None:
            yield f"(no backend)\n--- system prompt ---\n{system}"
            return
        pieces = []
        for chunk in self.backend.chat_stream(system, user_input,
                                              list(self.history)):
            pieces.append(chunk)
            yield chunk
        reply = "".join(pieces)
        self.history.append({"role": "user", "content": user_input})
        self.history.append({"role": "assistant", "content": reply})
        suggestion = self._suggest_memory(user_input)
        if suggestion:
            yield suggestion

    def repl(self, stream: bool = True) -> None:
        print("recallite — /help for commands, 'quit' to exit.\n")
        while True:
            try:
                user_input = input("You: ").strip()
            except (EOFError, KeyboardInterrupt):
                break
            if user_input.lower() in ("quit", "exit"):
                break
            if not user_input:
                continue
            print("Assistant: ", end="", flush=True)
            try:
                if stream:
                    for chunk in self.ask_stream(user_input):
                        print(chunk, end="", flush=True)
                    print("\n")
                else:
                    print(self.ask(user_input) + "\n")
            except ConnectionError as e:
                print(f"\n[backend error] {e}\n")
