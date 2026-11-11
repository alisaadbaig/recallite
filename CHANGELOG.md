# Changelog

> **Naming note:** before v0.16.0 this project was called *memlayer*. The
> entries below keep the historical name; see [0.16.0] for why we renamed.

All notable changes to **memlayer** are documented here.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) · Versioning: [SemVer](https://semver.org/).

## [Unreleased]

## [0.16.0] — 2026-11-11

### Changed
- **Project renamed: memlayer → recallite.** Pre-launch due diligence found
  the PyPI name `memlayer` already held (since 2025-11) by an unrelated
  project with a near-identical pitch; publishing under a variant would
  have collided on `import memlayer`. Renamed cleanly before first
  publication: package/import `recallite`, CLI `recallite`, env vars
  `RECALLITE_*` (the old `MEMLAYER_ALLOW_PRIVATE_URLS` /
  `MEMLAYER_PASSPHRASE` spellings are still honored), key-file defaults
  `~/.recallite_*`, loggers `recallite.*`. Databases are untouched — only
  the default filename changed (`recallite.db`); pass your existing path
  to keep using it. Historical changelog entries keep the old name.

## [0.15.0] — 2026-11-10

Phase 5: quality engineering + ecosystem. The last planned build before
the launch push.

### Added
- **Concurrency hardening** — found by this release's own threaded tests: Python's sqlite3 with `check_same_thread=False` raised `InterfaceError` under 8 concurrent writers, readers raced cursor stepping, and separate per-profile connections hit immediate `database is locked` on write-upgrade deadlocks. The connection now sits behind a statement-level lock proxy with eager row fetching inside the lock, full-transaction locks on multi-statement paths, `busy_timeout` + connect timeout, and a bounded exponential BUSY retry. Hammered 25×: threaded saves/reads/multi-store tests stable. Supported patterns documented: one store shared across threads, or one store per profile on a shared file.
- **Multi-session memory evaluation** (`multi_session` benchmark category, threshold ≥0.85): a deterministic three-session life timeline over 60 days with supersessions and an episodic tail; retrieval must return current truth and never the superseded past.
- **Cold/warm latency metrics**: process-cold open + first hybrid query vs warm p50, in `memlayer bench` output.
- **Before/after comparison**: `memlayer bench --compare old.json` prints per-category and latency deltas.
- **LangChain + LlamaIndex retrievers** (`memlayer[langchain]` / `memlayer[llamaindex]`): `as_langchain_retriever` / `as_llamaindex_retriever` — lazy imports with install hints, filters/strategy passthrough, explain signals in document metadata, optional `sanitize=True` redacting PII in retrieved text before it enters a chain.

### Fixed
- **Fusion recency bonus could jump ranks** (caught by the new multi-session eval): the v0.13 weights (5e-4 confidence/importance, 2e-3 recency) exceeded an adjacent top RRF rank gap (~2.6e-4) by ~8×, so a fresh irrelevant memory could leapfrog a 60-day-old semantically perfect one — "favorite food" lost biryani to yesterday's budget meeting. Bonuses are now strictly sub-gap (5e-5 each): they break near-ties, never reorder distinct ranks. Eval went 6/7 → 7/7; regression test added.

## [0.14.0] — 2026-11-09

Security remediation (external review of v0.13 — all five P0 findings
reproduced before fixing) + the MCP server.

### Security (P0)
- **Patient-name detection**: pluggable NER seam in the privacy engine (`make_name_detector`, spaCy-backed; Presidio-shaped `.detect()` objects plug in); `person`/`org`/`location` tokenizable; `--ner strict` refuses all content when the detector is missing or erroring (fail closed). The reviewer's exact reproduction now sanitizes fully.
- **Restoration identity split** (BREAKING): restore operations require a distinct restore credential (`--restore-key-file`); chat keys are 403 on `/v1/privacy/restore`; the `X-Memlayer-Restore` inline header is REMOVED — the chat path can never restore. Restore keys support `tenant=`, `categories=`, `destinations=` scoping; a key in both files refuses startup. Tenant identity is server-resolved from the key.
- **Session hardening** (BREAKING): session ids are server-minted and owner-bound; a client-supplied unknown/foreign id is 403, never auto-created; per-session locks; TTL + cap unchanged. Multi-instance note documented.
- **Schema-aware requests**: tools/tool_choice/response_format and assistant `tool_calls`/tool-role fields preserved with every string sanitized; unknown top-level or message fields rejected explicitly by name; malformed tool_call shapes rejected.
- **Structured-response DLP**: tool-call/function-call arguments and refusal strings scanned; unknown response message fields and logprobs stripped and reported.
- Fixed during remediation (found by its own tests): an EMPTY restoration allowlist fell back to the full default category set (falsy-set authorization hole) — now "restore nothing"; regression-tested.

### Added (P1)
- **MCP server** — `memlayer mcp` (`memlayer[mcp]` extra, MCP SDK 2.x): six sanitized tools (`memory_search/save/update/delete`, `privacy_check`, `policy_status`); all memory text redacted before the model-side client sees it; **no restore tool, by design**; stdio + streamable-HTTP transports, Bearer middleware on HTTP (loopback bind); guardrails/blocklist apply to MCP saves; integration tests cover tool listing, sanitized round-trips, supersession, guardrail refusal, and 401-vs-200 on the HTTP transport. Setup documented for Claude Desktop/Code and remote clients, including the documented limitation that MCP cannot intercept text typed directly into native chat UIs.
- Docs: PRIVACY_SHIELD.md remediation section, deployment (synthetic data), and an honest production-readiness assessment.

### Tests
- 15 new (144 pytest total): NER engine + gateway end-to-end patient-line capture, strict fail-closed (missing and erroring detectors), session minting/foreign-session rejection across two tenants, chat-key-cannot-restore, tenant-scoped and destination-scoped restore keys, per-key category limits, shared-credential startup refusal, empty-allowlist regression, unknown-field rejections, tool-flow preservation with sanitized arguments, response tool-call DLP + unknown-field stripping, MCP suite.

## [0.13.0] — 2026-11-08

Phase 3: retrieval excellence. The search path is now a modular pipeline —
tenant scoping → candidate generation (variant-fused lexical + full-scan
semantic) → metadata filters → RRF fusion with confidence/importance/
recency terms → optional cross-encoder rerank → adaptive cut →
explanations. Defaults unchanged; all 116 pre-existing tests passed
untouched.

### Added
- **Metadata filters** — `search(..., filters={"memory_type", "keyword", "source", "min_confidence", "min_importance", "created_after", "created_before"})`, applied after tenant scoping (never instead of it; candidate pool widens automatically). Also on `build_context(filters=...)` and `/search --type --keyword --source`.
- **Temporal ranking** — exponential recency (30-day half-life) joins confidence and importance in fusion; episodic memories weigh recency double.
- **Query reformulation** — deterministic, zero-inference: stopword-stripped OR variant (stops "what is my…" matching junk), AND co-occurrence variant for precision, raw query as recall fallback — merged by rank (RRF), in both the FTS and encrypted in-RAM paths.
- **Adaptive top-k** — `top_k="auto"` cuts where the fused score curve drops hardest (1–8 results; flat curves keep the cap).
- **Optional cross-encoder reranking** — `MemoryStore(..., reranker=CrossEncoderReranker())` (sentence-transformers, lazy); any object with `.rank(query, texts)` works; a failing reranker logs once and falls back to fusion order.
- **Retrieval explanations** — `explain=True` attaches per-hit: strategy, lexical/semantic ranks, cosine similarity, fused score, recency, confidence, importance, source, type, reranked flag, filters, variant count — JSON-serializable. `/search` renders a compact signal line per hit.
- 13 new tests: every filter key + date windows + tenant-scope preservation, recency on equal content, episodic double-weighting, adaptive cliff cut + unit cases, variant generation, stopword-noise defeat (plaintext and encrypted modes), reranker reorder + broken-reranker fallback, explanation fields, `/search` flags.

## [0.12.0] — 2026-11-08

Privacy Shield foundation: a vault-free privacy gateway. Design principle:
memlayer never stores sensitive values — the caller already owns the
original text, so sanitization hands the (ephemeral, session-scoped)
mapping back to the trusted application; SSN/PAN are excluded from every
mapping structurally; CVV/PIN content refuses the request outright.

### Added
- `memlayer/privacy.py` — Privacy Shield engine: `redact` / `tokenize`
  modes; session-scoped HMAC-SHA256 tokens (stable in-session, unlinkable
  across sessions, unforgeable); never-restore categories (SSN, PAN)
  redacted in every mode and absent from all mappings; CVV/CVC/PIN
  detection fails closed; context-gated DOB and MRN detectors; caller-
  supplied reference tokens (token→EHR-style locator, resolved inside the
  application boundary, value never held); authorized restore with
  category allowlists and TTL'd RAM-only sessions; output DLP.
- `memlayer/gateway.py` + `memlayer gateway` — OpenAI-compatible
  sanitizing proxy (loopback bind): `/v1/chat/completions` (every message
  role sanitized; uninspectable parts blocked), `/v1/models`, `/health`,
  `/v1/privacy/check`, `/v1/privacy/restore` (trusted-app restoration);
  Bearer-key auth from an operator-controlled key file (auto-created,
  chmod 600); inline restore via `X-Memlayer-Restore` intersected with the
  server allowlist; streaming served as fully-scanned SSE (no
  chunk-boundary leakage in v1); logs carry categories and counts, never
  values.
- `docs/PRIVACY_SHIELD.md` — architecture, security boundaries, fixed
  category policies, phase plan (MCP server with sanitized-only tools is
  P2), honest limitations, and the acceptance-criteria mapping.
- 21 acceptance tests, built around a payload-capturing mock upstream:
  sensitive values absent from outbound requests; CVV never forwarded;
  per-session token isolation under concurrent requests; model-invented
  tokens restore nothing; prompt injection cannot disable protection
  (config is not prompt state); output DLP; auth; fail-closed paths;
  no sensitive values in logs.

### Fixed
- **Output DLP could corrupt the gateway's own tokens** — a token whose
  10-hex suffix was all digits false-positived as a phone number, got
  redacted mid-token, and broke restoration (caught by the concurrency
  acceptance test flaking ~1-in-10). Privacy tokens and placeholders are
  now stashed behind sentinels before any detection runs, in both the
  sanitize and output-DLP paths — verified by 20 consecutive hammer runs.

### Notes
- Detection remains pattern-based and misses identifiers it has no
  pattern for; the detector seam accepts external engines (e.g. Presidio)
  in a later phase. Nothing here makes a deployment HIPAA/PCI compliant
  by itself; synthetic data only until independent review.

## [0.11.0] — 2026-11-08

Phase 2: intelligent memory lifecycle.

### Added
- **Memory types** — `memory_type` column (`semantic` | `preference` | `episodic` | `procedural`), heuristically classified from wording and overridable (`/save --type ...`, `memory_type=` in the API); shown in `/memories`.
- **Importance scoring** — `importance` column (0–1), defaulting by type (preference/procedural 0.7, semantic 0.5, episodic 0.4), settable via `--importance` / API; joins confidence and recency in lexical tie-breaking and hybrid RRF fusion.
- **Structured auto-extraction** — `/auto on` extraction now uses a strict JSON schema returning up to 3 typed facts with importance; candidates are validated (type whitelist, clamped importance), deduplicated against existing memories (semantic dedup included), and rendered as ready-to-confirm `/save --type ... --importance ...` commands. Garbage or empty model output stays silent; nothing is ever saved without confirmation.
- **Semantic duplicate detection** — `find_similar` adds an embedding-cosine pass (threshold 0.9, keyword-scoped) after token overlap, so paraphrased duplicates are intercepted at save time when an embedder is configured.
- **Consolidation** — `store.consolidate(apply=False)` / `/consolidate [apply]`: proposes groups of near-duplicate active memories per keyword; on apply, the highest-(confidence+importance) record stays active and the rest are superseded — history preserved, audited.
- **Temporal validity + source timestamps** — `valid_from` / `valid_until` / `observed_at` columns: a fact past its `valid_until` is historical (excluded from `all()`, every search strategy, and the prompt; kept for `/history`), enforced in the SQL retrieval paths too.
- **Retention management & true deletion** — `/retention <days>|off` hard-deletes superseded history beyond the window during the normal expiry sweep (active memories are never auto-deleted; audited); `/compact` rewrites the database (FTS optimize + VACUUM + WAL truncate) so deleted rows leave no byte-level traces — verified by raw-file scans in tests.
- 15 new tests: classification + overrides, flag parsing, importance ranking, temporal exclusion across every search path, semantic-paraphrase dedup + agent interception, consolidate propose/apply with history, retention purge (incl. never-touch-active), trace-free compaction, multi-fact extraction with invalid-candidate rejection, garbage-extraction silence, Phase-2 field round-trip in export/import, and v0.10→v0.11 schema auto-migration.

### Fixed
- Historical (`valid_until` passed) facts initially leaked through the FTS and vector search paths, which filtered by status only — caught by this release's own tests; the live-row predicate now applies in `_lexical_ranked`, `_vectors`, and `_by_id`.

### Changed
- `_row_to_dict` is now name-based (zipped with column names), eliminating the positional-index fragility that schema widening used to require.

## [0.10.0] — 2026-11-08

Phase-1 security hardening. Every defect was reproduced against the build
before fixing and has an adversarial regression test.

### Added
- **Encryption at rest** (`memlayer[crypto]`, AES-256-GCM + scrypt KDF): `MemoryStore(..., encryption_passphrase=...)` / `memlayer chat --encrypted` (passphrase via `MEMLAYER_PASSPHRASE`, `--passphrase-file`, or hidden prompt — never argv). Encrypts text, tags/keywords, and embedding vectors; metadata stays queryable. Wrong passphrase refused at open; encrypted profiles refuse to open or be switched into without their own key (per-profile keys, tenant-isolated). Existing plaintext databases migrate in place — including an FTS index rebuild and file vacuum so no plaintext survives in index tokens, free pages, or the WAL (a leak found and fixed during this build). Encrypted-mode lexical search scans the decrypted corpus in RAM (search p50 ~8.5 ms over 2,000 memories vs ~1.9 ms plaintext; measured, documented).
- **SSRF protection for `/task`** (`memlayer/netsec.py`): URLs resolving to loopback, private, link-local (cloud metadata), or reserved addresses are refused by default; every redirect hop is re-validated; redirect chains capped. Opt-out: `TaskManager(allow_private=True)` or `MEMLAYER_ALLOW_PRIVATE_URLS=1`. DNS-rebinding residual risk documented.
- **Structured audit log**: per-profile `audit_log` table + `memlayer.security` logger — unlock failures/successes, locks, password changes, guardrail blocks (with origin), injection-shield drops, SSRF blocks, profile switches, `/clear`, crypto enablement/migration. `store.audit_events(limit)`; unlock-gated and tenant-scoped; never contains memory text.
- 18 adversarial/regression tests: SSRF address matrix + per-hop redirect validation + loop cap, encryption roundtrip with raw-file plaintext scans, wrong/missing passphrase, in-place migration leak check, encrypted search in all strategies, cross-profile key refusal, shield-by-default, budget truncation, import-validation parity, audit lifecycle + tenancy, and a full tenant-isolation sweep (memories, search strategies, history, stats, export, context, blocklist, tasks).

### Changed
- **Secure by default**: a store with no `guardrails` argument now gets a default policy (PII warn, 2,000-char limit, injection shield). `guardrails=False` is the explicit opt-out. Previously, no guardrails meant no injection shield.
- **One validation path for all content**: `/import` now runs the same guardrails as `/save` — blocked records are skipped (counted + audited, reasons in the `/import` reply), redaction applies to imported text. Previously import bypassed guardrails entirely.
- **Strict token budget by default**: `build_context` caps at 600 tokens unless `max_context_tokens=None` is passed explicitly, and hard-truncates an oversized single memory (previously one huge memory could flood the prompt past any budget).
- Decrypted-rows cache: `all()` hot path cached and invalidated on mutation — found via the perf comparison (encrypted search was 20 ms before, 8.5 ms after; plaintext `build_context` also dropped 15 ms → 2.4 ms).

### Security
- Reproduced before fixing: task fetches reached 127.0.0.1/169.254.169.254; imports bypassed block-mode guardrails; injection-pattern memories reached the prompt without guardrails; a single oversized memory exceeded any token budget; migration initially left plaintext in the FTS index (caught by this release's own tests).

## [0.9.0] — 2026-11-08

### Added
- **UAT runner** — `memlayer uat`: runs release-shipped acceptance prompts (`memlayer/uat_prompts.json`, packaged in the wheel) against a REAL model (Ollama or any OpenAI-compatible server such as vLLM). Each case declares setup commands and an expected result (`contains_all`/`contains_any`/`not_contains`/`regex`/`memory_count`, case-insensitive); each runs in its own fresh database. The 10 shipped cases cover recall, temporal supersession, command-dispatch safety, PII redaction, secure-mode leakage while locked, injection obedience, and no-memory honesty. Reports show pass/fail per prompt with failure reason + reply excerpt, latency, the answering model, and memlayer version — text to stdout, JSON via `--report`; exit code 0 only on full pass (cron/CI-ready, nightly example in the README). Secure cases take their password from `--password-file` (auto-created random value, chmod 600); prompt files reference `{PASSWORD}` and `{LAST_ID}` tokens, never literals.
- Four regression tests run the full UAT path against mock model servers: a well-behaved model must pass 10/10, a leaky/injected model must FAIL on exactly the secure-leak and injection cases, an unreachable backend fails cleanly per-case, and the password file round-trips.

## [0.8.0] — 2026-11-08

### Added
- **Reproducible benchmark suite** — `memlayer bench` (also `--full`, `--json FILE`, `--embedder toy|st|ollama`): deterministic, seeded scorecard for recall@3, semantic recall (lexical vs hybrid — 0.00 vs 1.00, the hybrid story in one row), exact-token match, temporal correctness, contradiction handling, cross-profile privacy (zero-leak requirement), injection resistance (5 hostile memories incl. fence spoofing), token efficiency, and p50/p95/p99 latency. The default toy embedder is synonym-aware and hash-based, so results reproduce bit-for-bit with no model downloads; real models measurable via sentence-transformers or Ollama. The benchmark runs as a unit test, so **every release must pass its own benchmark**.

### Fixed
- **Hybrid search was rebuilding the numpy matrix on every query** (~10 ms overhead at 5k memories) — found by the benchmark's latency stage. The matrix is now built once when the vector cache fills: hybrid p50 dropped 12.7 ms → 2.7 ms (4.7×).
- Benchmark toy embedder uses 128-dim vectors (32 dims had too high a noise floor for distractor-heavy corpora — the benchmark caught its own first harness bug).

### Changed
- Repo hygiene: removed duplicate `CHANGELOG_v0.5.2.md`; moved `V0.5.2_FIXES.md` to `docs/REVIEW_FIXES_v0.5.2.md`.

## [0.7.0] — 2026-08-27

### Added
- **Hybrid semantic retrieval** — `store.search(query, strategy=...)` with `lexical` (BM25), `semantic` (full exact cosine scan over all active memories — no candidate pruning, so old memories are never missed), `hybrid` (Reciprocal Rank Fusion of both + confidence bonus), and `auto` (hybrid when an embedder is configured, else lexical). Solves the classic miss: "favorite food" now retrieves "loves biryani" despite zero word overlap, while exact tokens like "invoice 4521" still win via BM25.
- **Pluggable embedders** — `SentenceTransformerEmbedder` (pip extra) and `OllamaEmbedder` (talks to a local Ollama `/api/embed`, e.g. `nomic-embed-text` — zero Python installs); any object with `.encode(list[str])` works via `MemoryStore(..., embedder=...)`.
- **Automatic backfill** — memories saved before an embedder existed are embedded lazily on first semantic search (`ensure_embeddings()`), with an in-RAM vector cache invalidated on every mutation.
- Graceful degradation: a failing embedder logs once and falls back to lexical — semantic search can never break retrieval.

### Changed
- Superseded memories are excluded from semantic search (consistent with lexical).

## [0.6.0] — 2026-08-27

### Added
- **Tasks** — `/task add <name> <keyword> <url>` defines a named fetch task; `/task run` downloads the URL (http/https only, 500KB cap), strips HTML to plain text (~1200 chars), and saves it under the keyword with `tool_output` provenance (confidence 0.7). Re-running a task **supersedes** its previous fetch, so the prompt always carries exactly one current version. `/task list`, `/task remove`; all task operations respect the secure-mode lock, guardrails, and the persistent blocklist. Zero new dependencies.
- **Documentation** — `docs/SECURITY.md` (secure mode, setting/changing/resetting passwords, what is and isn't protected, guardrails, the four-layer injection defense, hardening checklist) and `docs/USAGE.md` (full command reference, 7 worked use cases, Python API, troubleshooting).

## [0.5.2] — 2026-08-27

Third independent review round: four findings, all reproduced, fixed, and
regression-tested.

### Fixed
- **Malformed `/import` could permanently brick a profile (critical)** — a record with non-list `tags` poisoned the database so every read (`/memories`, `/export`) crashed with `KeyError`, with no recovery path. Imports are now fully validated before any write (invalid batches rejected atomically with a clear error; coercible oddities normalized), and reads are defensive: corrupted tags can never crash a profile again — existing damaged databases self-heal on read.
- **Command prefix collisions could destroy data (critical)** — "/clearance levels at my job" matched `/clear` via `startswith` and silently wiped all memories; the same flaw affected every command ("/saveme", "/statistics", "/blocked-road", ...). Dispatch now matches the exact first token; unrecognized "/words" get an "Unknown command" reply instead of reaching the model or a command.
- **Prompt-fence spoofing (critical)** — a memory containing the literal text "END UNTRUSTED USER MEMORY" could fake the fence boundary and hand the model direct instructions (confirmed against a live model by the reviewer). Fence-marker strings inside memory text are now neutralized to "[removed marker]" at injection time, unconditionally — fence integrity no longer depends on optional guardrails.
- **`/replace` with a wrong id silently lied** — it reported "superseded" while leaving both contradictory facts active. The supersession UPDATE's rowcount is now checked: a bad id rolls back the whole operation and reports "No active memory found with id ... — nothing saved."

## [0.5.1] — 2026-08-26

Fixes from independent code review — thank you to the reviewer. All issues
were reproduced against the build before fixing; each now has a regression test.

### Fixed
- **Multi-profile search starvation (critical)** — FTS ranking applied its LIMIT before filtering by profile, so a profile with many dense matches could completely hide another profile's results. The user/status filter now happens inside the ranked CTE.
- **Secure-mode API bypass (critical)** — the lock was only enforced on `save()`; `all()`, `search()`, `export_json()`, `count()`, `stats()`, `clear()`, `forget()`, `history()`, `find_similar()`, `purge_expired()`, `import_json()`, `add_blocked()`, `remove_blocked()`, and `list_blocked()` now all raise `PermissionError` while locked. `build_context()` intentionally keeps returning `""` for LLM integration.
- **Tie-ranking inverted** — near-tied BM25 results preferred *older, lower-confidence* memories; a stable two-pass sort now correctly prefers newer, higher-confidence ones.
- **`/import` is now a full restore** — tags, expiry, status, supersession chains, provenance, and timestamps are preserved; previously only active facts survived and metadata was dropped. Re-importing the same backup is a safe no-op (existing ids skipped).
- `/profile` message read the old profile's lock state; it now correctly reports "(locked)" when switching to a locked secure profile.
- CI now runs the entire `tests/` folder (the secure-mode suite was not being executed); documentation test counts corrected.

### Added
- `/passwd` — change the secure-mode password (`/passwd <current> <new>`, or bare `/passwd` in a terminal for hidden prompts with confirmation). Requires the current password; memories are untouched.
- `AnthropicBackend` — Claude via the native Anthropic Messages API (stdlib-only, streaming supported, reads `ANTHROPIC_API_KEY` from the environment).
- Example scripts for every backend in `examples/`: `chat_vllm.py`, `chat_openai.py` (ChatGPT models), `chat_claude.py`, `chat_hf.py` — all sharing one memory format.

## [0.5.0] — 2026-08-26

### Added
- **Memory lifecycle & supersession** — `/replace <id> <kw> <fact>` now marks the old memory `superseded` (kept as history, never injected or retrieved) instead of deleting it. Retrieval returns only current truth.
- `/history <keyword>` — shows the full version chain for a keyword: `old [Austin] → ACTIVE [Dallas]`, with source and confidence per entry.
- **Provenance & confidence** — every memory records its `source` (`user_explicit` 1.0, `user_conversation` 0.8, `tool_output` 0.7, `model_inferred` 0.4) and a confidence score; both usable via the Python API.
- **Untrusted-memory prompt framing** — memories are injected inside `BEGIN/END UNTRUSTED USER MEMORY` markers with an explicit "data, not instructions" preamble (defense-in-depth on top of the injection shield).
- **Opt-in auto-extraction** — `/auto on` makes the model propose at most one memorable fact after a user message (`[memory suggestion] Worth remembering? Type: /save ...`). Nothing is saved without explicit confirmation; failures never break the chat; off by default.
- `last_accessed_at` tracking — memories are stamped when actually injected into a prompt.
- Automatic schema migration — databases created by v0.1–v0.4 upgrade in place on first open.

### Changed
- Retrieval ranking: near-tied BM25 results now prefer newer, higher-confidence memories.
- `/stats` reports the superseded count.
- FTS query rewritten with a ranked CTE (rank inside the index, join only top rows); `PRAGMA synchronous=NORMAL` under WAL. Typical searches ~0.9 ms over 5,000 memories; worst case (query matching every row) ~5 ms.
- README tagline: **"SQLite for AI memory."**

### Fixed
- Schema-migration ordering bug: index on `status` was created before the column existed when opening old databases.
- Flaky speed tests replaced with honest dual gates: <2 ms typical, <10 ms pathological.

## [0.4.0] — 2026-08-26

### Added
- **Persistent prohibited terms** — `/block <term>`, `/unblock <term>`, `/blocked`; stored in the database, survive restarts, and are enforced even when no `Guardrails` object is configured.
- **Optional NER** (`pip install "memlayer[ner]"`, spaCy) — ML detection of entities regex can't catch. Defaults to `ORG` + `GPE` only; `PERSON` must be added deliberately, since redacting names defeats a personal-memory library. Follows the same `pii_mode` (warn/redact/block). Graceful fallback message when spaCy or the model is missing.
- Repository infrastructure: `.gitignore` (protects `*.db` user memories), MIT `LICENSE`, GitHub Actions CI (Python 3.9/3.11/3.12, 60 tests).

## [0.3.0] — 2026-08-24

### Added
- **Guardrails module** — PII detection (email, phone, SSN, IP, API keys, Luhn-verified credit cards) with `allow | warn | redact | block` modes; static blocklist; length limits; **prompt-injection shield** filtering retrieved memories before they reach the model.
- **Streaming responses** for Ollama and OpenAI-compatible backends (`chat_stream`, `ask_stream`; REPL prints chunks live).
- **Conversation history** — rolling multi-turn window passed to backends.
- **Contradiction detection** — similar `/save` is intercepted with `/replace` and `/save!` options.
- Commands: `/search`, `/undo`, `/stats`, `/export`, `/import`, `/profile` (isolated multi-profile memory).
- **Memory expiry** — `/save --expires 30d ...` (m/h/d/w).
- Hidden password entry via `getpass` when typing `/enable` alone in a terminal.
- **CLI entry point** — `memlayer chat --backend ollama|openai|hf --secure --pii redact ...`.
- Token-budget-aware context (`max_context_tokens`, default 600).
- Adapter retries with exponential backoff and clean `ConnectionError`s; store transactions with rollback.
- Test suites: 35 pytest unit tests + 25-use-case runner (`tests/test_all_usecases.py`, CI-friendly exit codes, optional `--with-model` live tests).

### Changed
- Embedding model lazy-loads on first use.

## [0.2.0] — 2026-08-20

### Added
- **Secure mode** — `MemoryStore(..., secure=True)`: memory starts locked; `/enable <password>` sets (first use) or verifies; `/lock` re-locks. While locked, all memory commands are refused **and no memories are injected into the prompt**. Passwords stored as salted PBKDF2-HMAC-SHA256 (200k iterations), verified in constant time; unlock is per-session. Lock enforced in the store itself (`PermissionError`), not just the chat layer.
- **Keyword syntax** — `/save <keyword> <fact>`, with quoted multi-word keywords (`/save "favorite food" ...`); keywords indexed for search and shown in `/memories`.

## [0.1.0] — 2026-08-20

### Added
- Initial release: SQLite + FTS5 storage with BM25 ranking (WAL mode, multi-user isolation, atomic writes).
- Backends behind one interface: `OllamaBackend`, `OpenAICompatBackend` (vLLM, LM Studio, llama.cpp server, OpenAI, Groq), `HuggingFaceBackend` (in-process transformers).
- RAG-style context injection into the system prompt; model-agnostic memory ("memory follows the model").
- Commands: `/save`, `/memories`, `/forget`, `/clear`, `/help`; interactive REPL.
- Optional semantic reranking via sentence-transformers (`memlayer[semantic]`).
- Zero required dependencies (pure standard library core); pip-installable (`pyproject.toml`).
