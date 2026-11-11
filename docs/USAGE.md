# recallite Usage Guide

## Command reference

| Command | What it does |
|---|---|
| `/save <keyword> <fact>` | Remember a fact; quote multi-word keywords: `/save "favorite food" ...` |
| `/save --expires 30d <kw> <fact>` | Fact that auto-deletes (m/h/d/w) |
| `/save! <kw> <fact>` | Force-save even if a similar memory exists |
| `/replace <id> <kw> <fact>` | Supersede an old fact (kept as history, never injected) |
| `/history <keyword>` | Version chain: `old [Austin] → ACTIVE [Dallas]` |
| `/undo` | Delete the last saved memory |
| `/search [--type t] [--keyword k] [--source s] <query>` | Filtered search; results show confidence, importance, source, and which signals matched (`lex#1 sem#2`) |
| `/memories` | List everything (ids, keywords, timestamps) |
| `/forget <id>` / `/clear` | Delete one / all |
| `/stats` | Counts, keywords, superseded, DB size |
| `/export [file]` / `/import <file>` | Full backup / restore (metadata, expiry, history preserved) |
| `/save --type <t> --importance <0-1> ...` | Typed facts: `semantic` \| `preference` \| `episodic` \| `procedural` (auto-classified when omitted) |
| `/consolidate` / `/consolidate apply` | Propose, then execute, merging of near-duplicate memories (originals kept as history) |
| `/retention <days>` / `off` | Auto-delete superseded history older than N days (active memories never auto-deleted) |
| `/compact` | Rewrite the database so deleted rows leave no byte-level traces |
| `/task add <name> <kw> <url>` | Define a URL-fetch task |
| `/task run <name>` | Fetch now; re-runs supersede the previous fetch |
| `/task list` / `/task remove <name>` | Manage tasks |
| `/block <term>` / `/unblock` / `/blocked` | Prohibited terms (persistent) |
| `/auto on\|off` | Model suggests memorable facts; you confirm each |
| `/profile <name>` | Switch isolated memory profile |
| `/enable [pw]` / `/lock` / `/passwd` | Secure mode (see docs/SECURITY.md) |
| `/help` | Command list |

Anything else starting with `/` returns "Unknown command" — it is never sent
to the model and never partially matches a command ("/clearance" ≠ /clear).

## Use case 1 — personalize any local model

```
/save age my name is Ali and I am 36 years old
/save "home city" I live in Dallas
How is the weather where I live?        ← model answers about Dallas
```

Quit, switch from Ollama to vLLM to Claude — same `mem.db`, same memory.

## Use case 2 — keep facts current, not accumulated

```
/save city I live in Austin
...a year later...
/save city I moved to Dallas
→ "A similar memory exists [ab12cd34]..."
/replace ab12cd34 city I moved to Dallas
```

Now the model only ever sees Dallas; `/history city` shows the full story.

## Use case 3 — live data via tasks

Feed the model current information from the web, refreshed on demand:

```
/task add weather forecast https://wttr.in/Dallas?format=3
/task run weather
→ Task "weather": saved [x1y2z3] (forecast) ... 

What should I wear today?               ← model sees the fresh forecast
```

Re-running `/task run weather` tomorrow supersedes today's data — the prompt
always contains exactly one, current version. Fetched text is tagged
`tool_output` (confidence 0.7) so it never outranks what you said yourself.
Ideas: documentation pages your model should know, a status page, a prices
page, your public profile. Fetch only URLs you trust — see docs/SECURITY.md.

## Use case 4 — separate work and personal

```
/profile work
/save project the deadline for recallite v1.0 is October
/profile personal
/memories                               ← work facts invisible here
```

Profiles are fully isolated (search included) and each secure profile has
its own password.

## Use case 5 — temporary facts

```
/save --expires 2w trip I am in Karachi until the 15th
```

After two weeks the fact deletes itself — no stale travel plans haunting
your prompts.

## Use case 6 — let the model help you remember

```
/auto on
My sister Sara visits this weekend — we'll cook biryani, my favorite.
→ ...reply...
  [memory suggestions] Worth remembering? Type any of:
    /save --type preference --importance 0.8 food Ali's favorite dish is biryani
    /save --type episodic "family visit" Ali's sister Sara visits this weekend
```

Extraction is structured (typed facts with importance, up to 3 per
message), validated against a strict schema, and deduplicated — a fact you
already saved, even phrased differently, is not re-suggested. You always
confirm; nothing is saved silently. Costs one extra model call per message
while on, so toggle it when useful.

## Use case 8 — memory types and lifecycle hygiene

Every memory has a type — auto-classified from wording, or set explicitly:

| Type | Example | Default importance |
|---|---|---|
| `semantic` | "Ali is 36" | 0.5 |
| `preference` | "Ali prefers bullet-point answers" | 0.7 |
| `episodic` | "We discussed the roadmap yesterday" | 0.4 |
| `procedural` | "When deploying, run the migration first" | 0.7 |

Importance and confidence both feed retrieval ranking. Keep the store tidy:

```
/consolidate              ← shows near-duplicate groups, changes nothing
/consolidate apply        ← best record stays active, rest become history
/retention 90             ← superseded history deleted after 90 days
/compact                  ← true deletion: no traces left in the file
```

Facts can also carry temporal validity via the Python API
(`valid_from=` / `valid_until=`): a fact whose validity has ended is
treated as historical — excluded from search and the prompt, kept in
`/history`.

## Use case 7 — backup and migration

```
/export backup.json          ← everything: history, expiry, provenance
```

Move the file to a new machine, `/import backup.json` — identical state,
including superseded chains. Re-importing the same file is a safe no-op.

## Python API in 10 lines

```python
from recallite import MemoryStore, MemoryAgent, OllamaBackend, Guardrails

store = MemoryStore("mem.db", user_id="ali", secure=True,
                    guardrails=Guardrails(pii_mode="redact"))
agent = MemoryAgent(store, OllamaBackend("llama3.2"))

agent.ask("/enable mypassword")
agent.ask("/save age I am 36")
print(agent.ask("How old am I?"))          # → "You're 36!"
for chunk in agent.ask_stream("Tell me a story about my city"):
    print(chunk, end="", flush=True)       # streaming
```

Direct store access for building your own integrations: `store.save()`,
`store.search()`, `store.build_context()` (returns the ready-to-inject
prompt block), `store.supersede()`, `store.export_json()`.

## Troubleshooting

- `ModuleNotFoundError: recallite` → run `pip install -e .` from the folder
  containing `pyproject.toml`, inside your active venv
- `[backend error] Backend unreachable` → the model server is down; check
  `ollama serve` / your `vllm serve` terminal, then just resend
- "Memory is locked" → `/enable <password>` (see docs/SECURITY.md)
- Saves being refused → check `/blocked` and your Guardrails `pii_mode`
- Model doesn't know a saved fact → `/search <topic>` to confirm it's
  stored; remember only ACTIVE memories are injected (`/history <keyword>`)
