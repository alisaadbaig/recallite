# recallite — Use-Case Test Plan (for your vLLM setup)

Your environment: vLLM serving `openai/gpt-oss-20b` at `http://localhost:8000/v1`.

## How to run

```bash
cd <project root>            # folder containing pyproject.toml
source .venv/bin/activate    # if you use a venv

# Library use cases only (no model needed) — ~5 seconds:
python3 tests/test_all_usecases.py

# Everything including live-model tests (vLLM must be running):
python3 tests/test_all_usecases.py --with-model

# Show full tracebacks on failure:
python3 tests/test_all_usecases.py --with-model -v
```

Expected: `RESULT: 25/25 passed` without a model, `28/28` with `--with-model`.
The script exits with code 0 on success, 1 on any failure (CI-friendly), and
works even if `pip install -e .` was skipped (it finds the package next to it).

## Use-case coverage map

| # | Use case | What is verified | Automated | Manual step |
|---|----------|------------------|-----------|-------------|
| UC1 | Personalize the model | `/save <keyword> <fact>` stores; fact appears in the injected context; quoted multi-word keywords; bad syntax → usage help, nothing stored | ✅ | Type `/save age I am 36`, then a plain question, and see the fact used |
| UC2 | Permanent memory | Facts survive closing and reopening the store (restart) | ✅ | Quit the chat, relaunch, ask "how old am I?" |
| UC3 | Manage memories | `/memories`, `/search`, `/forget <id>`, `/undo`, `/stats`, `/clear` | ✅ | Run each command once |
| UC4 | Update facts | Similar save intercepted with suggestions; `/replace` updates in place; `/save!` keeps both | ✅ | Save your age twice with different values |
| UC5 | Secure mode | Starts locked; `/enable` sets then verifies password; wrong password rejected; locked = zero prompt leakage; restart relocks but keeps password; direct Python API raises PermissionError | ✅ | Also test hidden typing: type `/enable` alone in a real terminal |
| UC6 | Guardrails | PII redact and block modes; Luhn-checked cards; blocklist; length limit; injection-pattern memories filtered before reaching the prompt | ✅ | Save your real email with `--pii redact` and check `/memories` |
| UC7 | Expiring facts | Expired memories vanish; invalid durations rejected | ✅ | `/save --expires 1m trip flight at 6pm`, wait 60s, `/memories` |
| UC8 | Backup / migration | `/export` + `/import` round-trips all memories with keywords | ✅ | Move the JSON to another machine and import there |
| UC9 | Multi-profile | `/profile work` fully isolates memory spaces | ✅ | Switch profiles and list memories in each |
| UC10 | Speed at scale | 5,000 memories; average search must stay under 5 ms | ✅ | — |
| UC11 | Live model answers from memory | Model reply contains the saved name and age | ✅ (`--with-model`) | — |
| UC11b | Streaming | Response arrives in multiple chunks | ✅ (`--with-model`) | Watch words appear one by one in the REPL |
| UC11c | Conversation history | Model recalls the previous turn | ✅ (`--with-model`) | Ask a follow-up question referencing your last message |

## Manual-only checks (things a script cannot see)

1. **Hidden password input** — in a real terminal, type `/enable` with no argument: a `Password (hidden):` prompt must appear and your typing must be invisible.
2. **Streaming feel** — in `recallite chat` / `agent.repl()`, long answers must render progressively, not appear after a wait.
3. **Backend-down behavior** — stop vLLM (Ctrl-C its terminal), send a chat message: you must get a clean `[backend error] Backend unreachable...` line, not a Python traceback. Restart vLLM and confirm chatting resumes.
4. **Full restart ritual with the real model** — save a fact, quit, relaunch, ask about it. The model must answer correctly from `recallite.db`.

## Before-release checklist

- [ ] `python3 tests/test_all_usecases.py --with-model` → all passed
- [ ] `pytest tests/ -v` → 41 passed (unit-level suite)
- [ ] Manual checks 1–4 above done in a real terminal
- [ ] Fresh venv on a clean folder: `pip install -e .` then quickstart works first try
