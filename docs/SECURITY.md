# recallite Security Guide

Everything about protecting your memories: secure mode, passwords, guardrails,
and how recallite defends the model against malicious memory content.

## 1. Secure mode

Secure mode password-locks a profile's memory. While locked, **every** memory
operation is refused — commands, the Python API, and prompt injection alike.
The model literally knows nothing about you until you unlock.

Turn it on when creating the store (per database + profile):

```python
store = MemoryStore("mem.db", user_id="ali", secure=True)
```
or from the CLI: `recallite chat --secure`

### Setting a password (first time)

The **first** `/enable` on a secure profile sets the password:

```
/enable mypassword123        ← inline
/enable                      ← bare, in a terminal: hidden typing prompt
```

Minimum 4 characters. Each profile (`user_id`) has its own password.

### Daily use

| Command | Effect |
|---|---|
| `/enable <password>` | Unlock for this session |
| `/enable` (bare, terminal) | Same, with hidden typing |
| `/lock` | Lock immediately |
| quit / restart | Always relocks automatically |

### Changing the password

Requires the current password; memories are untouched:

```
/passwd oldpass newpass      ← inline
/passwd                      ← bare: hidden prompts + confirmation
```

Rules: wrong current password → "Password unchanged"; new password under
4 chars → refused; the change takes effect immediately (old password stops
working, new one persists across restarts).

### Forgot the password? (reset)

There is **no recovery mechanism — by design**. A backdoor for you is a
backdoor for an attacker. Your options:

1. **Restore a backup** you made while unlocked (`/export backup.json`
   → new database → `/import backup.json`). Make backups a habit.
2. **Manual reset** (requires file access): delete the password record —
   memories survive, and the next `/enable` sets a fresh password:
   ```bash
   sqlite3 mem.db "DELETE FROM settings WHERE user_id='ali';"
   ```

That option 2 exists highlights the current boundary, so read the next
section carefully.

### What secure mode does and does not protect

**Protects against:** the app and the model. While locked, nothing can read,
write, list, search, export, or inject memories — enforced inside the store
itself (`PermissionError`), not just in the chat layer — and your password is
stored only as a salted PBKDF2-HMAC-SHA256 hash (200,000 iterations),
verified in constant time. The raw password appears nowhere in the file.

**Protecting the file itself:** turn on encryption at rest (next section).
Without it, memory *text* in the `.db` file is readable by anyone holding
the file (never your password). With it, the file holds only ciphertext.

## 1b. Encryption at rest

```python
store = MemoryStore("mem.db", user_id="ali",
                    encryption_passphrase="a long passphrase")
```
or `recallite chat --encrypted` (passphrase from `RECALLITE_PASSPHRASE`,
`--passphrase-file`, or a hidden prompt — never from argv, where other
processes could read it).

- AES-256-GCM via the optional `cryptography` package
  (`pip install "recallite[crypto]"`); key derived with scrypt from your
  passphrase; random per-user salt; fresh nonce per value. No hand-rolled
  ciphers.
- **Encrypted:** memory text, tags/keywords, and embedding vectors
  (embeddings leak meaning). **Plaintext:** ids, timestamps, status,
  source, confidence — metadata needed for queries, carrying no content.
- A wrong passphrase is refused at open (verifier check), and a database
  with encrypted profiles refuses to open without a passphrase.
- **Existing databases migrate automatically**: on first open with a
  passphrase, plaintext rows are encrypted in place, the full-text index is
  rebuilt (it held plaintext tokens), and the file is vacuumed so no
  plaintext survives in free pages or the WAL.
- Per-profile keys: switching into an encrypted profile without its key is
  refused — one tenant's key never touches another's rows.
- Honest trade-offs: lexical search runs over the decrypted corpus in RAM
  (measured: search p50 ~8.5 ms over 2,000 memories vs ~1.9 ms plaintext —
  fine for chat, not built for millions of rows); the passphrase-derived
  key lives in process memory while the store is open (at-rest encryption
  protects the file, not a compromised process); **`/export` writes a
  plaintext backup by design** — guard exported files accordingly; and
  there is no passphrase recovery: lose it and the content is gone.

## 2. Guardrails: filtering what enters memory

```python
from recallite import Guardrails, MemoryStore
guard = Guardrails(pii_mode="redact", blocklist=["projectx"], max_length=2000)
store = MemoryStore("mem.db", guardrails=guard)
```

**PII detection** (email, phone, SSN, IP, API keys, Luhn-verified credit
cards) with four modes: `allow` | `warn` (default) | `redact` (store
`[EMAIL]` instead of the value) | `block` (refuse the save). Regex-based, so
it catches structured formats, not free-text like "ali at example dot com".

**NER (optional)** — ML detection of organizations/locations via spaCy
(`pip install "recallite[ner]"`). Defaults to ORG + GPE; add `"PERSON"`
deliberately — redacting names defeats a personal-memory library.

**Prohibited terms** — static `blocklist=[...]` plus a persistent list
managed in chat: `/block <term>`, `/unblock <term>`, `/blocked`. The
persistent list survives restarts and applies even with no Guardrails object.

**Secure by default (v0.10):** a store created without a `Guardrails`
argument gets a default policy — PII *warnings*, the 2,000-char length
limit, and the prompt-injection shield. Pass your own `Guardrails(...)` to
tune it, or `guardrails=False` to disable filtering entirely (deliberate
opt-out). Guardrails filter on the way **in** — enabling them later does
not clean previously saved memories.

**The same validation runs on every entry path**: `/save`, `/import`
(blocked records are skipped, counted, and audited — redaction applies to
imported text too), and `/task` fetches.

## 3. Defending the model from memory (injection)

Memories are user data, and data can be hostile. recallite layers defenses:

1. **Untrusted framing** — memories enter the prompt inside
   `BEGIN/END UNTRUSTED USER MEMORY` markers with an explicit instruction
   that the content is data, never commands.
2. **Fence integrity** — any occurrence of those marker strings *inside*
   memory text is neutralized to `[removed marker]` at injection time,
   unconditionally, so data cannot fake the fence boundary.
3. **Injection shield** (on by default since v0.10) — memories matching
   known injection patterns ("ignore previous instructions", ...) are
   dropped before reaching the prompt at all, and each drop is audited.
4. **Provenance weighting** — every memory records its source:
   `user_explicit` (1.0) > `user_conversation` (0.8) > `tool_output` (0.7,
   e.g. `/task` URL fetches) > `model_inferred` (0.4). Web-fetched content
   never carries the authority of what you typed yourself.

5. **Strict token budget** — context injection is capped at 600 tokens by
   default; an oversized memory is hard-truncated rather than allowed to
   flood the prompt. (`max_context_tokens=None` disables, explicitly.)

No prompt-level defense is perfect against every model; these layers reduce
risk, they don't abolish it. Treat `/task` URLs like you treat links: fetch
sources you trust.

## 3b. Fetching the web safely: SSRF protection for `/task`

A task URL is user data pointed at the network. By default recallite
refuses to fetch anything that resolves to a non-public address —
loopback (your vLLM/Ollama ports), private ranges, link-local (cloud
metadata at 169.254.169.254), reserved — and re-validates **every redirect
hop**, so a public URL cannot bounce the fetch into your internal network.
Redirect chains are capped. Blocked attempts are audited (`ssrf.blocked`).

Fetching from your own machines is a deliberate opt-out:
`TaskManager(store, allow_private=True)` or
`RECALLITE_ALLOW_PRIVATE_URLS=1`.

Known residual risk (documented, not hidden): hostname validation resolves
DNS, then the fetch resolves again — a hostile DNS server answering
differently per query (DNS rebinding) could evade the check. Mitigated by
requiring all resolved addresses to be public; full single-resolution
pinning is out of scope for a stdlib-only fetcher.

## 3c. Audit log

Security-relevant events are recorded per profile in an `audit_log` table
and mirrored to the `recallite.security` stdlib logger: failed and
successful unlocks, locks, password changes, guardrail blocks (with
origin: save/import), injection-shield drops, SSRF blocks, profile
switches, `/clear`, and encryption enablement/migration. Read them with
`store.audit_events(limit=50)` — unlock required, tenant-scoped, and no
memory text is ever written into the log.

## 4. Practical hardening checklist

- Use `secure=True` for any profile holding personal facts
- Run with `--pii redact` (or `block` in strict environments)
- `/block` your project codenames and other never-store terms
- `/export` backups regularly *while unlocked*; store them as carefully as
  the database itself (exports are plain JSON)
- One profile per person; profiles are isolated, each with its own password
- Turn on encryption at rest for any profile holding personal facts
  (`encryption_passphrase=` / `--encrypted`) and store the passphrase in a
  password manager — there is no recovery
- Leave SSRF protection on; use `RECALLITE_ALLOW_PRIVATE_URLS=1` only when
  you really mean to fetch from your own machines
- Review `store.audit_events()` after anything surprising

## 5. Reporting security issues

Found a bypass? Please open a GitHub issue (or contact the maintainer
privately for sensitive findings). This project has a track record of
reproducing, fixing, and regression-testing reported issues quickly — see
CHANGELOG.md for the history.
