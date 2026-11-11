"""
recallite.tasks — named tasks that fetch a URL and store the result as memory.

    /task add btc price https://example.com/btc     (define once)
    /task run btc                                    (fetch -> memory)
    /task run btc                                    (re-run SUPERSEDES the old fetch)

Design safety:
- fetched text is saved with source="tool_output" (confidence 0.7), so it
  never outranks what the user said explicitly
- content passes through guardrails (PII / blocklist / length) like any save,
  and the injection shield + fence defusing apply at prompt time
- http(s) only, response size capped, HTML stripped to plain text
"""

from __future__ import annotations

import html as _html
import re
import time
from typing import Optional

from .netsec import SSRFError, safe_urlopen, validate_public_url

MAX_BYTES = 500_000          # never download more than this
DEFAULT_MAX_CHARS = 1200     # keep memories prompt-sized


def fetch_url_text(url: str, max_chars: int = DEFAULT_MAX_CHARS,
                   timeout: int = 20, allow_private: bool = False) -> str:
    """Fetch a URL and reduce it to plain text (stdlib only).

    SSRF-safe by default: refuses URLs that resolve to loopback, private,
    link-local (cloud metadata) or otherwise non-public addresses, and
    re-validates every redirect hop. Pass allow_private=True (or set
    RECALLITE_ALLOW_PRIVATE_URLS=1) to deliberately fetch from your own
    machines.
    """
    with safe_urlopen(url, timeout=timeout,
                      allow_private=allow_private,
                      user_agent="recallite") as resp:
        raw = resp.read(MAX_BYTES)
    text = raw.decode("utf-8", errors="replace")
    # strip scripts/styles, then all tags, then collapse whitespace
    text = re.sub(r"(?is)<(script|style|noscript)[^>]*>.*?</\1>", " ", text)
    text = re.sub(r"(?s)<[^>]+>", " ", text)
    text = _html.unescape(text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        raise ValueError("URL returned no readable text.")
    return text[:max_chars]


class TaskManager:
    """Named fetch-tasks stored per user; results become memories."""

    def __init__(self, store, allow_private: bool = False):
        self.store = store
        self.allow_private = allow_private
        self._db = store._db
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS tasks (
                user_id        TEXT NOT NULL,
                name           TEXT NOT NULL,
                keyword        TEXT NOT NULL,
                url            TEXT NOT NULL,
                last_run       TEXT,
                last_memory_id TEXT,
                PRIMARY KEY (user_id, name)
            )""")
        self._db.commit()

    def _require_unlocked(self):
        self.store._require_unlocked()

    def add(self, name: str, keyword: str, url: str) -> str:
        self._require_unlocked()
        name = name.strip().lower()
        try:
            validate_public_url(url, allow_private=self.allow_private)
        except SSRFError as e:
            self.store._audit("ssrf.blocked", f"task add {name}: {url}")
            return str(e)
        self._db.execute(
            "INSERT OR REPLACE INTO tasks "
            "(user_id, name, keyword, url, last_run, last_memory_id) "
            "VALUES (?, ?, ?, ?, "
            " (SELECT last_run FROM tasks WHERE user_id=? AND name=?),"
            " (SELECT last_memory_id FROM tasks WHERE user_id=? AND name=?))",
            (self.store.user_id, name, keyword.strip().lower(), url,
             self.store.user_id, name, self.store.user_id, name))
        self._db.commit()
        return (f'Task "{name}" saved: fetch {url} into keyword '
                f'"{keyword.strip().lower()}". Run it with: /task run {name}')

    def remove(self, name: str) -> str:
        self._require_unlocked()
        cur = self._db.execute(
            "DELETE FROM tasks WHERE user_id=? AND name=?",
            (self.store.user_id, name.strip().lower()))
        self._db.commit()
        return (f'Removed task "{name}".' if cur.rowcount
                else f'No task named "{name}".')

    def list(self) -> str:
        self._require_unlocked()
        rows = self._db.execute(
            "SELECT name, keyword, url, last_run FROM tasks "
            "WHERE user_id=? ORDER BY name", (self.store.user_id,)).fetchall()
        if not rows:
            return "No tasks defined. Add one with: /task add <name> <keyword> <url>"
        return "Tasks:\n" + "\n".join(
            f'  {r[0]}  ->  "{r[1]}"  from {r[2]}'
            f'  (last run: {r[3] or "never"})' for r in rows)

    def run(self, name: str, max_chars: int = DEFAULT_MAX_CHARS) -> str:
        self._require_unlocked()
        name = name.strip().lower()
        row = self._db.execute(
            "SELECT keyword, url, last_memory_id FROM tasks "
            "WHERE user_id=? AND name=?",
            (self.store.user_id, name)).fetchone()
        if not row:
            return f'No task named "{name}". See /task list'
        keyword, url, last_id = row

        try:
            text = fetch_url_text(url, max_chars=max_chars)
        except Exception as e:
            return f'Task "{name}" failed to fetch {url}: {e}'

        # re-runs supersede the previous fetch (if it is still active)
        supersedes = None
        if last_id:
            still_active = self._db.execute(
                "SELECT 1 FROM memories WHERE id=? AND user_id=? "
                "AND status='active'",
                (last_id, self.store.user_id)).fetchone()
            if still_active:
                supersedes = last_id

        try:
            rec = self.store.save(
                f"[from {url}] {text}", keyword=keyword,
                source="tool_output", supersedes=supersedes)
        except (ValueError, PermissionError) as e:
            return f'Task "{name}" fetched OK but save was refused: {e}'

        self._db.execute(
            "UPDATE tasks SET last_run=?, last_memory_id=? "
            "WHERE user_id=? AND name=?",
            (time.strftime("%Y-%m-%d %H:%M:%S"), rec["id"],
             self.store.user_id, name))
        self._db.commit()
        sup = f' (superseded previous fetch [{supersedes}])' if supersedes else ""
        return (f'Task "{name}": saved [{rec["id"]}] ({keyword}) '
                f'{len(text)} chars from {url}{sup}')
