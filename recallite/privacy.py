"""
recallite.privacy — vault-free privacy engine (Privacy Shield core).

Three modes:
    redact    irreversible placeholders; no mapping exists anywhere
    tokenize  opaque session-scoped tokens; the mapping is returned to the
              CALLER (who already owns the original text) and/or held in
              process RAM with a TTL — never written to disk
    restore   authorized replacement of tokens for ALLOWED categories only

Structural guarantees (not policy promises):
  - SSN, payment PAN: redacted in every mode, excluded from every mapping.
    No code path can return them, because the data never exists.
  - CVV/CVC/PIN: detection causes the whole text to be REFUSED (fail
    closed); sensitive authentication data is never stored or forwarded.
  - Tokens are HMAC-SHA256 under a random per-session key: stable within a
    session, unlinkable across sessions, unforgeable. A token the model
    invents resolves to nothing.
  - Detector failure => PrivacyError (fail closed), never silent pass-through.

This module stores nothing. There is no vault.
"""

from __future__ import annotations

import hmac
import hashlib
import os
import re
import time
from dataclasses import dataclass, field
from typing import Optional

from .guardrails import detect_pii

# ---------------------------------------------------------------------------
# category policy — fixed, not configurable at runtime
# ---------------------------------------------------------------------------

NEVER_RESTORE = frozenset({"ssn", "credit_card"})
BLOCKING = frozenset({"cvv"})          # presence refuses the whole request
TOKENIZABLE = frozenset({"email", "phone", "ip_address", "api_key",
                         "dob", "mrn", "person", "org", "location"})

_CONTEXT_PATTERNS = {
    # context-gated: only match when the surrounding words say what it is
    "cvv": re.compile(r"\b(?:cvv|cvc|cvv2|security\s+code|card\s+code)"
                      r"\W{0,6}(\d{3,4})\b", re.I),
    "dob": re.compile(r"\b(?:dob|date\s+of\s+birth|born(?:\s+on)?)"
                      r"\W{0,6}(\d{1,2}[/\-.]\d{1,2}[/\-.]\d{2,4})", re.I),
    "mrn": re.compile(r"\b(?:mrn|medical\s+record\s+(?:number|no\.?))"
                      r"\W{0,6}([A-Za-z0-9][A-Za-z0-9\-]{3,})", re.I),
}


class PrivacyError(ValueError):
    """Raised to FAIL CLOSED: the text must not be forwarded."""


class SpacyNameDetector:
    """NER-based name/org/location detection (spaCy). Implements the
    pluggable detector seam: any object with .detect(text) -> {category:
    [values]} fits — a Microsoft Presidio adapter plugs in the same way.

        pip install "recallite[ner]" && python -m spacy download en_core_web_sm

    Thread-safe (inference guarded by a lock for the threaded gateway).
    Raises on failure so strict mode can fail closed; the caller decides.
    """

    LABELS = {"PERSON": "person", "ORG": "org", "GPE": "location"}

    def __init__(self, model: str = "en_core_web_sm",
                 categories: tuple = ("person",)):
        self.model_name = model
        self.categories = set(categories)
        self._nlp = None
        import threading
        self._lock = threading.Lock()

    def _load(self):
        if self._nlp is None:
            import spacy
            self._nlp = spacy.load(self.model_name)
        return self._nlp

    def detect(self, text: str) -> dict[str, list[str]]:
        nlp = self._load()
        with self._lock:
            doc = nlp(text)
        found: dict[str, list[str]] = {}
        for ent in doc.ents:
            cat = self.LABELS.get(ent.label_)
            if cat in self.categories:
                found.setdefault(cat, []).append(ent.text)
        return found


def make_name_detector(ner: str = "auto",
                       categories: tuple = ("person",)):
    """ner: 'off' -> None; 'auto' -> spaCy if available, else None;
    'strict' -> spaCy REQUIRED (raises PrivacyError if unavailable)."""
    if ner == "off":
        return None
    try:
        det = SpacyNameDetector(categories=categories)
        det._load()
        return det
    except Exception as e:
        if ner == "strict":
            raise PrivacyError(
                f"Required name detector unavailable ({e}); refusing to "
                f"operate without it. Install: pip install \"recallite[ner]\" "
                f"&& python -m spacy download en_core_web_sm") from e
        print(f"[recallite] name detection unavailable ({e}); "
              f"continuing with pattern detectors only.")
        return None


def detect_sensitive(text: str, name_detector=None,
                     strict: bool = False) -> dict[str, list[str]]:
    """Layered detection: base PII patterns + context-gated clinical and
    payment-auth patterns + optional NER (names/orgs/locations). Returns
    {category: [values]}. Raises PrivacyError if detection fails — and in
    strict mode, if the required name detector is missing or erroring.
    Never silently passes."""
    if strict and name_detector is None:
        raise PrivacyError(
            "Strict mode requires a name detector and none is configured; "
            "refusing content.")
    try:
        found = dict(detect_pii(text))
        for name, pattern in _CONTEXT_PATTERNS.items():
            vals = [m.group(1) for m in pattern.finditer(text)]
            if vals:
                found.setdefault(name, []).extend(vals)
    except PrivacyError:
        raise
    except Exception as e:
        raise PrivacyError(f"Detection failed; refusing content: {e}") from e
    if name_detector is not None:
        try:
            for cat, vals in name_detector.detect(text).items():
                if vals:
                    found.setdefault(cat, []).extend(vals)
        except Exception as e:
            if strict:
                raise PrivacyError(
                    f"Name detection failed; refusing content: {e}") from e
            print(f"[recallite] name detector error ({e}); pattern "
                  f"detectors only for this text.")
    return found


# ---------------------------------------------------------------------------
# sessions — ephemeral, RAM-only, TTL-bound
# ---------------------------------------------------------------------------

@dataclass
class PrivacySession:
    """Holds one session's token key and mapping. RAM only; never persisted.
    The mapping NEVER contains NEVER_RESTORE or BLOCKING categories."""
    ttl_seconds: int = 900
    key: bytes = field(default_factory=lambda: os.urandom(32))
    mapping: dict = field(default_factory=dict)      # token -> (category, value)
    refs: dict = field(default_factory=dict)         # token -> caller reference
    created: float = field(default_factory=time.time)

    def expired(self) -> bool:
        return time.time() - self.created > self.ttl_seconds

    def token_for(self, category: str, value: str) -> str:
        digest = hmac.new(self.key, f"{category}\x00{value}".encode(),
                          hashlib.sha256).hexdigest()[:10]
        return f"[{category.upper()}_{digest}]"


class PrivacyShield:
    """The engine. Stateless apart from the sessions it is handed."""

    def __init__(self, mode: str = "tokenize", name_detector=None,
                 strict: bool = False):
        """name_detector: object with .detect(text)->{category:[values]}
        (see SpacyNameDetector / make_name_detector). strict=True fails
        closed whenever the detector is missing or erroring."""
        if mode not in ("redact", "tokenize"):
            raise ValueError("mode must be 'redact' or 'tokenize'")
        self.mode = mode
        self.name_detector = name_detector
        self.strict = strict

    def _detect(self, text: str) -> dict[str, list[str]]:
        return detect_sensitive(text, name_detector=self.name_detector,
                                strict=self.strict)

    # -- token opacity ----------------------------------------------------
    # Our own tokens must be invisible to the detectors: a token's hex
    # suffix can be all digits and false-positive as a phone number, and
    # DLP must never corrupt a token it is supposed to protect. Tokens
    # (and bare placeholders) are stashed behind \x00 sentinels before any
    # detection runs, and put back afterwards.

    _ANY_TOKEN_RE = re.compile(r"\[([A-Z_]+)(?:_[0-9a-f]{10})?\]")

    def _stash_tokens(self, text: str) -> tuple[str, list]:
        spans: list[str] = []

        def _stash(m):
            spans.append(m.group(0))
            return f"\x00T{len(spans) - 1}\x00"

        return self._ANY_TOKEN_RE.sub(_stash, text), spans

    @staticmethod
    def _unstash_tokens(text: str, spans: list) -> str:
        for i, s in enumerate(spans):
            text = text.replace(f"\x00T{i}\x00", s)
        return text

    # -- sanitize --------------------------------------------------------

    def sanitize(self, text: str, session: Optional[PrivacySession] = None,
                 refs: Optional[dict] = None) -> tuple[str, dict]:
        """Returns (sanitized_text, report).

        report = {"categories": {cat: count}, "mapping": {token: value}}
        The mapping is returned to the CALLER; this engine keeps nothing.
        NEVER_RESTORE values are replaced by bare placeholders and appear
        in no mapping. BLOCKING categories raise PrivacyError.

        refs: optional {value: reference} supplied by a trusted caller —
        the token then maps to the reference (e.g. an EHR record locator),
        never to the value, and resolution happens inside the caller's own
        boundary.
        """
        text, _spans = self._stash_tokens(text)   # existing tokens: opaque
        found = self._detect(text)

        blocked = sorted(set(found) & BLOCKING)
        if blocked:
            raise PrivacyError(
                f"Content contains prohibited authentication data "
                f"({', '.join(blocked)}); request refused. Such values are "
                f"never stored or forwarded.")

        counts: dict[str, int] = {}
        mapping: dict[str, str] = {}
        # longest-first so overlapping values replace cleanly
        pairs = sorted(((cat, v) for cat, vals in found.items()
                        for v in set(vals)),
                       key=lambda p: len(p[1]), reverse=True)
        for cat, value in pairs:
            if value not in text:
                continue
            counts[cat] = counts.get(cat, 0) + text.count(value)
            if cat in NEVER_RESTORE or self.mode == "redact" \
                    or session is None:
                replacement = f"[{cat.upper()}]"
            else:
                replacement = session.token_for(cat, value)
                ref = (refs or {}).get(value)
                if ref is not None:
                    session.refs[replacement] = ref
                    mapping[replacement] = f"ref:{ref}"
                else:
                    session.mapping[replacement] = (cat, value)
                    mapping[replacement] = value
            text = text.replace(value, replacement)
        return self._unstash_tokens(text, _spans), \
            {"categories": counts, "mapping": mapping}

    # -- restore ---------------------------------------------------------

    TOKEN_RE = re.compile(r"\[([A-Z_]+)_([0-9a-f]{10})\]")

    def restore(self, text: str, session: PrivacySession,
                allowed_categories: Optional[set] = None) -> tuple[str, dict]:
        """Replace tokens with originals for ALLOWED categories only.
        Trusted-application boundary only. Fails closed: expired session,
        unknown/forged tokens, and disallowed categories all restore
        nothing. NEVER_RESTORE categories cannot be allowed — their values
        are not in any mapping. Returns (text, report)."""
        if session.expired():
            raise PrivacyError("Privacy session expired; restoration refused.")
        # None means "caller imposes no narrowing" (defaults apply); an
        # EMPTY set means "restore nothing" — a falsy-set `or` here once
        # silently widened an empty allowlist to everything tokenizable.
        if allowed_categories is None:
            allowed = set(TOKENIZABLE)
        else:
            allowed = {c.lower() for c in allowed_categories}
        allowed -= set(NEVER_RESTORE) | set(BLOCKING)   # structural no-op
        restored, refused = 0, 0

        def _sub(m):
            nonlocal restored, refused
            token = m.group(0)
            hit = session.mapping.get(token)
            if hit is None:
                if token in session.refs:
                    refused += 1          # refs resolve in the app, not here
                return token              # unknown/forged/ref: unchanged
            cat, value = hit
            if cat not in allowed:
                refused += 1
                return token
            restored += 1
            return value

        out = self.TOKEN_RE.sub(_sub, text)
        return out, {"restored": restored, "refused_or_unknown": refused,
                     "refs_pending": [t for t in session.refs if t in text]}

    # -- output DLP ------------------------------------------------------

    def scan_output(self, text: str) -> tuple[str, dict]:
        """Model output is untrusted. If raw sensitive values appear in a
        response (the model guessed, memorized, or echoed something it
        should not have), redact them and report. Never raises on
        BLOCKING here — output is redacted, not refused. Privacy tokens
        in the output are ours and are exempt from scanning."""
        text, _spans = self._stash_tokens(text)
        found = self._detect(text)
        counts: dict[str, int] = {}
        # longest-first, exactly like sanitize(): otherwise replacing a
        # short value (a DOB) inside a longer detected span (an NER PERSON
        # covering "Name DOB 05/14/1985") breaks the longer value's lookup
        # and the name leaks — found by the streaming NER test
        pairs = sorted(((cat, v) for cat, vals in found.items()
                        for v in set(vals)),
                       key=lambda p: len(p[1]), reverse=True)
        for cat, v in pairs:
            if v in text:
                counts[cat] = counts.get(cat, 0) + text.count(v)
                text = text.replace(v, f"[{cat.upper()}]")
        return self._unstash_tokens(text, _spans), {"redacted": counts}


# ---------------------------------------------------------------------------
# incremental output DLP — streaming without chunk-boundary leaks
# ---------------------------------------------------------------------------

class StreamScanner:
    """Scan a model's output stream incrementally and emit sanitized text
    with low latency, WITHOUT the classic chunk-boundary leak (an SSN
    split across two chunks evading per-chunk scanning).

        scanner = StreamScanner(shield)
        for chunk in upstream:
            yield scanner.feed(chunk)     # may be "" while holding back
        yield scanner.flush()

    How it stays safe:
    - Emitted text always trails the stream frontier by at least
      HOLDBACK characters, so any detectable pattern that could still be
      completed by future chunks lies entirely in the unemitted tail
      (every pattern we detect is far shorter than HOLDBACK).
    - The emit cut happens only at whitespace, so a token
      ([EMAIL_1a2b3c4d5e]), an email address, or any other unbroken run
      can never straddle the boundary half-scanned.
    - Each emitted span is scan_output()-sanitized as a whole; flush()
      scans whatever remains. Redaction counts accumulate in .report.

    Latency cost: emission trails the frontier by ~HOLDBACK characters
    (a couple of sentences). A pathological stream with no whitespace at
    all buffers until flush — correct, just not incremental.
    """

    HOLDBACK = 96          # > the longest detectable pattern or token

    def __init__(self, shield: "PrivacyShield"):
        self.shield = shield
        self._raw = ""
        self.report: dict[str, int] = {}

    def _scan(self, text: str) -> str:
        out, rep = self.shield.scan_output(text)
        for k, v in rep["redacted"].items():
            self.report[k] = self.report.get(k, 0) + v
        return out

    def _match_spans(self, text: str) -> list[tuple[int, int]]:
        """Spans of every detectable value currently in the buffer. The
        frontier is >= HOLDBACK past any candidate cut, so any pattern
        shorter than HOLDBACK that could straddle the cut is already
        COMPLETE in the buffer and therefore in this list."""
        PAD = 8
        spans = []
        # context-gated patterns: protect the FULL match (gate + value) —
        # a cut between "MRN " and its value made each half unmatchable
        # and leaked the value (found by the streaming NER test)
        for pattern in _CONTEXT_PATTERNS.values():
            for m in pattern.finditer(text):
                spans.append((max(0, m.start(0) - PAD), m.end(0) + PAD))
        found = detect_sensitive(text,
                                 name_detector=self.shield.name_detector,
                                 strict=self.shield.strict)
        for vals in found.values():
            for v in set(vals):
                start = 0
                while True:
                    i = text.find(v, start)
                    if i < 0:
                        break
                    spans.append((max(0, i - PAD), i + len(v) + PAD))
                    start = i + 1
        return spans

    def feed(self, chunk: str) -> str:
        self._raw += chunk
        limit = len(self._raw) - self.HOLDBACK
        if limit <= 0:
            return ""
        spans = self._match_spans(self._raw)

        def whitespace_cut(at: int) -> int:
            for i in range(at, 0, -1):
                if self._raw[i - 1].isspace():
                    return i
            return 0

        # cut at whitespace (no unbroken run — email, privacy token — can
        # straddle), then move it left past any detected match it would
        # split (a spaced PAN or phone number is NOT an unbroken run: the
        # first version of this scanner leaked card numbers split at
        # their internal spaces — caught by the every-position harness)
        cut = whitespace_cut(limit)
        moved = True
        while moved and cut > 0:
            moved = False
            for s, e in spans:
                if s < cut < e:
                    cut = whitespace_cut(s)
                    moved = True
                    break
        if cut <= 0:
            return ""
        emit, self._raw = self._raw[:cut], self._raw[cut:]
        return self._scan(emit)

    def flush(self) -> str:
        emit, self._raw = self._raw, ""
        return self._scan(emit) if emit else ""


class PresidioDetector:
    """Microsoft Presidio adapter for the name-detector seam
    (pip install "recallite[presidio]"). Maps Presidio entities onto
    recallite categories; anything mapping to ssn/credit_card is still
    governed by the structural never-restore policy, and detection stays
    layered — Presidio ADDS recall on top of the built-in patterns.

        shield = PrivacyShield("tokenize", name_detector=PresidioDetector())
    """

    DEFAULT_MAP = {"PERSON": "person", "LOCATION": "location",
                   "NRP": "org", "ORGANIZATION": "org",
                   "EMAIL_ADDRESS": "email", "PHONE_NUMBER": "phone",
                   "US_SSN": "ssn", "CREDIT_CARD": "credit_card",
                   "IP_ADDRESS": "ip_address",
                   "MEDICAL_LICENSE": "mrn"}

    def __init__(self, entities: dict | None = None,
                 language: str = "en", score_threshold: float = 0.4):
        self.map = dict(entities or self.DEFAULT_MAP)
        self.language = language
        self.score_threshold = score_threshold
        self._engine = None
        import threading
        self._lock = threading.Lock()

    def _load(self):
        if self._engine is None:
            from presidio_analyzer import AnalyzerEngine
            self._engine = AnalyzerEngine()
        return self._engine

    def detect(self, text: str) -> dict[str, list[str]]:
        engine = self._load()
        with self._lock:
            results = engine.analyze(text=text, language=self.language,
                                     entities=list(self.map))
        found: dict[str, list[str]] = {}
        for r in results:
            if r.score < self.score_threshold:
                continue
            cat = self.map.get(r.entity_type)
            if cat:
                found.setdefault(cat, []).append(text[r.start:r.end])
        return found
