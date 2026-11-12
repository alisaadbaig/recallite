# recallite Privacy Shield — vault-free privacy gateway

**Goal:** an AI model never needs access to original sensitive identifiers,
while authorized applications can still display original information —
**without recallite ever becoming a store of sensitive values.**

## The design decision that shapes everything

Classic "privacy gateways" keep a detokenization vault: a database mapping
tokens back to real SSNs, card numbers, and patient identifiers. That vault
is the highest-value attack target such a system can create, and we refuse
to build it. Instead:

1. **The caller already owns the original text.** Sanitization returns the
   token↔value mapping *to the caller* (the trusted application), inside the
   same trust boundary the data came from. recallite persists nothing.
2. **Gateway sessions are ephemeral.** When the gateway restores a response
   inline for the authenticated caller, the mapping lives in process RAM,
   scoped to a session id, expiring on a short TTL. It never touches disk.
3. **Never-restore categories are structural, not policy.** SSN, payment
   PAN, and CVV/CVC are *excluded from mappings at detection time*. There is
   no code path that can return them — not a permission check that could be
   bypassed, but an absence of data.
4. **References over values.** For patient data, trusted applications can
   supply source references (e.g. an EHR record locator) alongside text; the
   token maps to the *reference*, and resolution happens in the application
   against its own authorized systems. recallite never sees or stores what
   the reference points to.
5. **Payment data belongs to PCI-compliant providers.** We detect and block
   or redact PANs; we do not tokenize-for-restoration. An organization that
   needs reversible payment tokens should integrate an established,
   audited provider — the gateway leaves a seam for that, it does not
   reimplement it.

## Security boundaries

```
 TRUSTED APPLICATION BOUNDARY          │        UNTRUSTED (model side)
                                       │
 app (owns original data) ──┐          │
                            ▼          │
                   recallite gateway    │
                   1 detect            │
                   2 sanitize ────────────▶ upstream model (vLLM/Ollama/
                   3 session map (RAM, │     OpenAI-compatible) sees ONLY
                     TTL, never disk)  │     sanitized text
                   4 output DLP ◀──────────  model response
                   5 restore (allowed  │
                     categories only)  │
                            ▼          │
 app (may resolve refs against its     │
      own EHR / PCI provider)          │
```

- Everything left of the bar runs on infrastructure the operator controls.
- The model only ever receives sanitized text; the gateway's outbound
  payload is the enforcement point, and tests capture it to prove the
  original values are absent.
- Model output is treated as untrusted: it gets DLP-scanned (a raw PAN or
  SSN appearing in a response is redacted and audited), and model text can
  never authorize a restoration — restoration rights come from the
  caller's API key and the server's category allowlist, full stop.

## Detection categories and their fixed policies

| Category | Detect | Tokenize/restore | Policy |
|---|---|---|---|
| CVV/CVC, PINs | context-gated | — | **blocked**: request refused, value never stored or forwarded |
| Payment PAN (Luhn) | yes | never | redacted in every mode; restoration structurally impossible |
| SSN | yes | never | redacted in every mode; restoration structurally impossible |
| Email, phone, IP, API keys | yes | session tokens | restorable to authorized callers |
| Dates of birth (context-gated) | yes | session tokens | restorable to authorized callers |
| Medical record numbers (context-gated) | yes | session tokens / caller refs | restorable to authorized callers |
| Person/org/location names | via optional NER or caller-supplied refs | refs preferred | resolution inside the application boundary |

Detection is layered (regex + Luhn + context gates + optional spaCy NER),
and the detector interface is pluggable — an organization can mount
Microsoft Presidio or a clinical NER behind the same seam. **Known
limitation, stated plainly:** pattern-based detection misses free-text
identifiers it has no pattern for ("the patient from room 4"). That is why
modes exist: `redact`/`tokenize` reduce exposure, they do not make text
provably anonymous, and nothing here makes a deployment HIPAA- or
PCI-compliant by itself — compliance needs risk assessment, contracts,
and independent validation on top.

## Operating modes

- **redact** — irreversible placeholders (`[SSN]`, `[EMAIL]`). No mapping
  exists anywhere.
- **tokenize** — opaque, unpredictable, session-scoped tokens
  (`[EMAIL_3f9a1c]`): HMAC-SHA256 of the value under a random per-session
  key, so tokens are stable within a session (the model can refer to them
  coherently), unlinkable across sessions, and unforgeable (a guessed or
  model-invented token resolves to nothing). Never-restore categories are
  redacted even in this mode.
- **authorized restore** — the trusted app (or the gateway, inline, for the
  authenticated caller) replaces tokens with originals for *allowed
  categories only*, within its own boundary, before display. Fails closed:
  an unknown token stays a token; a forged token restores nothing.

## v0.14 security remediation (external review response)

All five P0 findings were reproduced against v0.13 before fixing:

1. **Name detection** — the engine now takes a pluggable name detector
   (`make_name_detector("auto"|"off"|"strict")`, spaCy-backed; any object
   with `.detect(text)` fits, so a Microsoft Presidio adapter plugs into
   the same seam). `person`/`org`/`location` are tokenizable categories.
   `--ner strict` FAILS CLOSED: if the detector is missing or erroring,
   content is refused rather than passed with weaker protection. NER does
   not guarantee de-identification; see Known limitations.
2. **Restoration identity split** — gateway keys (chat) and restore keys
   (trusted restoration services) are distinct credentials in separate
   files; a key present in both files refuses to start. Chat clients
   cannot restore anything; the inline-restore header was REMOVED.
   Restore keys can be scoped per tenant (`tenant=`), per category
   (`categories=`), and per destination (`destinations=`). Tenant
   identity is resolved server-side from the key, never from a client
   field.
3. **Sessions** — server-minted (`secrets.token_urlsafe`), bound to the
   owning tenant, owner-enforced on reuse (foreign or invented ids are
   403, never silently created), TTL-bound, count-capped, per-session
   locks for concurrency-safe mapping access. Multi-instance: sessions
   are per-process; use one instance or sticky routing.
4. **Schema-aware requests** — known top-level fields, message fields,
   content part types, and tool/tool_call shapes are preserved with every
   string sanitized (tool definitions, schemas, arguments included);
   anything unknown is rejected explicitly with the field named, never
   forwarded.
5. **Structured-response DLP** — assistant text, refusals, tool-call and
   function-call arguments are all scanned; unknown response fields and
   logprobs are stripped and reported, so no model-generated text reaches
   the client unscanned.

Found during this remediation by its own tests: an empty restoration
allowlist fell back to the full default set (falsy-set bug) — an
authorization hole, fixed and regression-tested.

## MCP server (sanitized tools only)

`recallite mcp --db mem.db [--transport http --port 8765]` exposes:
`memory_search`, `memory_save`, `memory_update`, `memory_delete`,
`privacy_check`, `policy_status`. Every output that carries memory text is
privacy-sanitized (redact mode) before the model-side client sees it, and
**no restore tool exists by design** — restoration remains a
trusted-application privilege of the gateway's `/v1/privacy/restore`.
stdio transport trusts the local OS user (standard for MCP); http
transport requires a Bearer key and binds loopback — put TLS termination
in front for anything further.

Client setup: Claude Desktop/Code — add a stdio server command
`recallite mcp --db /path/mem.db --user you`; ChatGPT and other remote MCP
clients — run `--transport http` behind your TLS proxy and register
`https://your-host/mcp` with the Bearer key.

**Documented limitation:** MCP cannot intercept text a person types
directly into a native chat interface — the platform receives it before
any tool runs. Mandatory pre-model privacy enforcement requires routing
the application through `recallite gateway`.

## Deployment (synthetic data only)

```bash
pip install "recallite[crypto,ner,mcp]"
python -m spacy download en_core_web_sm
recallite gateway --upstream http://localhost:8000/v1 \
    --mode tokenize --ner strict --restore person,dob,mrn,email
recallite mcp --db mem.db --transport http --port 8765   # optional
```

Keys are auto-created (chmod 600) at ~/.recallite_gateway_key,
~/.recallite_restore_key, ~/.recallite_mcp_key — rotate by replacing the
files and restarting. Both servers bind 127.0.0.1; expose them only behind
a TLS reverse proxy you control. Use synthetic data until your own
security and compliance review is complete.

## Production readiness assessment (honest)

Ready now: local/single-tenant deployments guarding non-regulated PII in
prompts to self-hosted or API models, with synthetic-data validation.
NOT ready without further work and independent review: regulated PHI/PCI
production traffic. Gaps that remain regardless of test counts: detection
recall is bounded (pattern + NER miss unanticipated identifier forms —
measure on your own corpus before trusting); sessions are per-process;
key files are a minimal credential system (no rotation automation, no
OAuth); no rate limiting; compliance requires risk assessment, BAAs/
contracts, and operational controls no library can provide.

## Incremental streaming DLP (v0.17)

`recallite gateway` now streams for real. Model deltas pass through a
`StreamScanner`: emission trails the stream frontier by a 96-character
holdback window, cuts happen only at whitespace, and the cut is moved off
any detected span *including its gating context* — so an SSN, a spaced
card number, or "MRN 908123" split across upstream chunks is still caught
whole. Tool-call argument deltas are buffered and emitted only after a
full scan (JSON fragments cannot be scanned piecewise). Verified by an
every-split-position adversarial harness (every boundary of every secret,
plus 1–17-char chunk sizes, with NER enabled). Latency cost: output trails
by roughly a sentence. A no-whitespace stream buffers until flush —
correct, just not incremental. `--stream-mode buffered` remains available.

Building this found and fixed a bug in the BUFFERED path too: overlapping
detections (an NER person-span containing a DOB) were replaced
shortest-first, breaking the longer value's replacement — the name could
leak. Output scanning now replaces longest-first, like sanitize always did.

## Presidio detector (v0.17)

`PrivacyShield(name_detector=PresidioDetector())` mounts Microsoft
Presidio on the same seam as the spaCy detector
(`pip install "recallite[presidio]"`): configurable entity→category
mapping and score threshold, layered ON TOP of the built-in patterns.
Entities mapping to ssn/credit_card stay governed by the structural
never-restore policy.

## What ships in which phase

- **P1 (this release):** `recallite/privacy.py` engine (modes, sessions,
  never-restore, output DLP, fail-closed) + `recallite/gateway.py`
  OpenAI-compatible sanitizing proxy (`recallite gateway`) with API-key
  auth, per-role message sanitization, uninspectable-content blocking,
  restore endpoint for trusted callers, audit events + acceptance tests
  against a payload-capturing mock upstream.
- **P2:** MCP server exposing *sanitized* memory tools (search/save with
  the same engine; no detokenization tool will ever be exposed to a model).
- **P3:** streaming with incremental DLP (v1 buffers and scans complete
  responses before emitting — the honest way to prevent chunk-boundary
  leakage), richer admin/monitoring surface, Presidio adapter.

## Acceptance criteria mapping (from the Privacy Shield spec)

| # | Criterion | Status |
|---|---|---|
| 1–3 | names/DOB/SSN/PAN absent from captured model requests | **tested now** (mock upstream captures outbound payloads) |
| 4 | CVV blocked, never stored | **tested now** (request refused; value in no store, no audit detail) |
| 5–6 | restore only for authorized recipients | **tested now** (API key + category allowlist; SSN/PAN structurally excluded) |
| 7 | tenant A tokens unresolvable by tenant B | **tested now** (per-session HMAC keys; cross-session tokens restore to nothing) |
| 8 | streaming cannot leak | **by construction in v1**: responses are fully scanned before emission; incremental streaming is P3 |
| 9 | model-generated tokens cannot trigger restoration | **tested now** (unknown/forged tokens never resolve; model text carries no authority) |
| 10 | tool/file content cannot bypass policy | **tested now**: tool definitions, tool_calls arguments, and tool-role messages sanitized; unknown fields rejected |
| 11 | prompt injection cannot disable protection | protection is server-side config, not prompt state (tested: injection text passes through sanitization unchanged in authority) |
| 12 | failed detection ⇒ fail-closed | **tested now** (detector exception ⇒ request refused) |
| 13 | no sensitive data in logs | audit events carry categories and counts, never values (tested) |
| 14 | existing recallite functionality intact | full regression suites must stay green |
| 15 | API + MCP auth tests | **tested now** (distinct chat/restore credentials; MCP Bearer middleware integration test) |
| 16 | concurrent request isolation | per-request/session state only; concurrency test in P1 |
| 17 | persistence/migrations/rotation | no sensitive persistence exists by design; session TTL tested |
