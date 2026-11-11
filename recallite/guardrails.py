"""
recallite.guardrails — content filters for what enters and leaves memory.

Two checkpoints:
  1. on_save   : scan text BEFORE it is stored  (PII, blocklist, length)
  2. on_inject : scan memories BEFORE they enter the model prompt
                 (prompt-injection patterns)

Modes for PII: "allow" | "warn" | "redact" | "block"
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

# ---------------------------------------------------------------------------
# PII patterns
# ---------------------------------------------------------------------------

_PII_PATTERNS: dict[str, re.Pattern] = {
    "email":      re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]{2,}\b"),
    "phone":      re.compile(r"(?<!\d)(\+?\d{1,3}[\s-]?)?(\(?\d{3}\)?[\s-]?)\d{3}[\s-]?\d{4}(?!\d)"),
    "ssn":        re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    "ip_address": re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
    "api_key":    re.compile(r"\b(sk-[A-Za-z0-9_-]{16,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    "credit_card": re.compile(r"\b(?:\d[ -]?){13,19}\b"),
}

_INJECTION_PATTERNS = [
    re.compile(p, re.IGNORECASE) for p in (
        r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions",
        r"disregard\s+(all\s+)?(previous|prior|system)",
        r"you\s+are\s+now\s+(a|an)\s",
        r"new\s+system\s+prompt",
        r"</?system>",
        r"\bjailbreak\b",
        r"do\s+not\s+follow\s+the\s+system",
    )
]


def _luhn_ok(digits: str) -> bool:
    """Luhn checksum — filters out random number strings from card matches."""
    nums = [int(c) for c in digits if c.isdigit()]
    if not 13 <= len(nums) <= 19:
        return False
    total, parity = 0, len(nums) % 2
    for i, n in enumerate(nums):
        if i % 2 == parity:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_pii(text: str) -> dict[str, list[str]]:
    """Return {pii_type: [matches]} found in text."""
    found: dict[str, list[str]] = {}
    for name, pattern in _PII_PATTERNS.items():
        matches = [m.group(0) for m in pattern.finditer(text)]
        if name == "credit_card":
            matches = [m for m in matches if _luhn_ok(m)]
        if matches:
            found[name] = matches
    return found


def redact_pii(text: str) -> str:
    """Replace every detected PII value with a [TYPE] placeholder."""
    for name, values in detect_pii(text).items():
        for v in values:
            text = text.replace(v, f"[{name.upper()}]")
    return text


def detect_injection(text: str) -> list[str]:
    """Return list of prompt-injection patterns matched in text."""
    return [p.pattern for p in _INJECTION_PATTERNS if p.search(text)]


# ---------------------------------------------------------------------------
# Optional NER (ML-based entity detection) — pip install recallite[ner]
# ---------------------------------------------------------------------------

class NERDetector:
    """
    Detects named entities (PERSON, ORG, GPE/locations...) using spaCy.
    Lazy-loaded: the model loads on first use, not at import.

        pip install spacy
        python -m spacy download en_core_web_sm
    """

    def __init__(self, entities: tuple = ("PERSON", "ORG", "GPE"),
                 model: str = "en_core_web_sm"):
        self.entities = set(entities)
        self.model_name = model
        self._nlp = None
        self._failed = False

    def _load(self):
        if self._nlp is None and not self._failed:
            try:
                import spacy
                self._nlp = spacy.load(self.model_name)
            except Exception as e:
                self._failed = True
                print(f"[recallite] NER unavailable ({e}). "
                      f"Install with: pip install spacy && "
                      f"python -m spacy download {self.model_name}")
        return self._nlp

    def detect(self, text: str) -> dict[str, list[str]]:
        """Return {entity_label: [values]} for configured entity types."""
        nlp = self._load()
        if nlp is None:
            return {}
        found: dict[str, list[str]] = {}
        for ent in nlp(text).ents:
            if ent.label_ in self.entities:
                found.setdefault(ent.label_.lower(), []).append(ent.text)
        return found




@dataclass
class GuardrailResult:
    allowed: bool
    text: str                       # possibly redacted
    warnings: list[str] = field(default_factory=list)


@dataclass
class Guardrails:
    """
    Configurable filter policy.

        guard = Guardrails(pii_mode="redact", blocklist=["password"],
                           ner=True, ner_entities=("ORG", "GPE"))
        store = MemoryStore("mem.db", guardrails=guard)

    NER notes: requires spaCy (optional). Careful with "PERSON" in a
    personal-memory library — it would redact "my name is Ali". Default
    entities when ner=True are ("ORG", "GPE") for that reason; add
    "PERSON" explicitly only if you really want names removed.
    """
    pii_mode: str = "warn"                 # allow | warn | redact | block
    blocklist: list[str] = field(default_factory=list)
    max_length: int = 2000
    shield_injection: bool = True          # filter memories at inject time
    ner: bool = False                      # ML entity detection (needs spaCy)
    ner_entities: tuple = ("ORG", "GPE")
    ner_model: str = "en_core_web_sm"
    extra_blocklist_provider: object = None  # callable -> list[str] (set by store)

    def __post_init__(self):
        self._ner = (NERDetector(self.ner_entities, self.ner_model)
                     if self.ner else None)

    def _full_blocklist(self) -> list[str]:
        terms = list(self.blocklist)
        if callable(self.extra_blocklist_provider):
            terms += list(self.extra_blocklist_provider())
        return terms

    # -- checkpoint 1: before saving ------------------------------------

    def on_save(self, text: str) -> GuardrailResult:
        warnings: list[str] = []

        if len(text) > self.max_length:
            return GuardrailResult(
                False, text,
                [f"Memory too long ({len(text)} chars, max {self.max_length})."])

        low = text.lower()
        hit = next((w for w in self._full_blocklist() if w.lower() in low), None)
        if hit:
            return GuardrailResult(
                False, text, [f'Blocked: contains prohibited term "{hit}".'])

        # regex PII + optional NER entities, all handled by pii_mode
        found = detect_pii(text)
        if self._ner is not None:
            for label, values in self._ner.detect(text).items():
                found.setdefault(label, []).extend(values)

        if found:
            kinds = ", ".join(found)
            if self.pii_mode == "block":
                return GuardrailResult(
                    False, text, [f"Blocked: contains PII ({kinds})."])
            if self.pii_mode == "redact":
                text = redact_pii(text)
                if self._ner is not None:
                    for label, values in self._ner.detect(text).items():
                        for v in values:
                            text = text.replace(v, f"[{label.upper()}]")
                warnings.append(f"PII redacted ({kinds}).")
            elif self.pii_mode == "warn":
                warnings.append(f"Warning: this memory contains PII ({kinds}).")

        return GuardrailResult(True, text, warnings)

    # -- checkpoint 2: before prompt injection --------------------------

    def on_inject(self, memories: list[dict]) -> tuple[list[dict], list[str]]:
        """Filter retrieved memories; drop ones with injection patterns."""
        if not self.shield_injection:
            return memories, []
        safe, dropped = [], []
        for m in memories:
            if detect_injection(m["text"]):
                dropped.append(m["id"])
            else:
                safe.append(m)
        warnings = ([f"Shielded {len(dropped)} memory(ies) with "
                     f"injection-like content: {', '.join(dropped)}"]
                    if dropped else [])
        return safe, warnings
