"""
recallite.crypto — encryption at rest for memory content.

    store = MemoryStore("mem.db", encryption_passphrase="correct horse ...")

What is encrypted: memory text, tags (they contain keywords), and embedding
vectors (embeddings leak meaning). What stays plaintext: ids, timestamps,
status, source, confidence — metadata needed for queries, carrying no
memory content.

Design:
- AES-256-GCM via the `cryptography` package (optional extra:
  pip install "recallite[crypto]"). We do NOT hand-roll ciphers.
- Key derived from the passphrase with scrypt (stdlib hashlib),
  n=2^14, r=8, p=1; random 16-byte salt per user, stored in the database.
- A verifier token (encryption of a known constant) detects a wrong
  passphrase immediately instead of yielding garbage.
- Ciphertext format: text columns "enc1:<base64(nonce||ct)>",
  blobs b"ENC1" + nonce + ct. Fresh random 12-byte nonce per value.

Honest trade-offs (documented, not hidden):
- SQLite's FTS5 index cannot search ciphertext, so in encrypted mode
  lexical search runs over the decrypted corpus in RAM. At personal scale
  (thousands of memories) this costs ~1 ms; it is not built for millions.
- The FTS index still receives ciphertext tokens via triggers; they are
  useless noise and never queried in encrypted mode.
- The passphrase (and derived key) lives in process memory while the store
  is open. Encryption at rest protects the FILE, not a compromised process.
"""

from __future__ import annotations

import base64
import hashlib
import os

TEXT_MARKER = "enc1:"
BLOB_MARKER = b"ENC1"
_VERIFY = b"recallite-verify-v1"


class CryptoUnavailable(RuntimeError):
    pass


class WrongPassphrase(ValueError):
    pass


def _load_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM
    except ImportError as e:
        raise CryptoUnavailable(
            "Encryption at rest requires the 'cryptography' package: "
            'pip install "recallite[crypto]"') from e


def derive_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 8:
        raise ValueError("Encryption passphrase must be at least 8 characters.")
    return hashlib.scrypt(passphrase.encode("utf-8"), salt=salt,
                          n=2 ** 14, r=8, p=1, dklen=32)


def is_encrypted_text(value: str) -> bool:
    return isinstance(value, str) and value.startswith(TEXT_MARKER)


class MemoryCrypto:
    """Encrypts/decrypts memory content with a passphrase-derived key."""

    def __init__(self, passphrase: str, salt: bytes):
        self._aesgcm = _load_aesgcm()(derive_key(passphrase, salt))

    # -- verifier ------------------------------------------------------

    def make_verifier(self) -> str:
        return self.encrypt_text(_VERIFY.decode())

    def check_verifier(self, token: str) -> bool:
        try:
            return self.decrypt_text(token) == _VERIFY.decode()
        except Exception:
            return False

    # -- text ----------------------------------------------------------

    def encrypt_text(self, plaintext: str) -> str:
        nonce = os.urandom(12)
        ct = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return TEXT_MARKER + base64.b64encode(nonce + ct).decode("ascii")

    def decrypt_text(self, value: str) -> str:
        if not is_encrypted_text(value):
            return value                     # plaintext passthrough
        raw = base64.b64decode(value[len(TEXT_MARKER):])
        try:
            return self._aesgcm.decrypt(raw[:12], raw[12:], None) \
                       .decode("utf-8")
        except Exception as e:
            raise WrongPassphrase(
                "Cannot decrypt memory — wrong passphrase or corrupted "
                "data.") from e

    # -- blobs (embeddings) --------------------------------------------

    def encrypt_blob(self, blob: bytes | None) -> bytes | None:
        if blob is None:
            return None
        nonce = os.urandom(12)
        return BLOB_MARKER + nonce + self._aesgcm.encrypt(nonce, blob, None)

    def decrypt_blob(self, blob: bytes | None) -> bytes | None:
        if blob is None or not blob.startswith(BLOB_MARKER):
            return blob
        raw = blob[len(BLOB_MARKER):]
        try:
            return self._aesgcm.decrypt(raw[:12], raw[12:], None)
        except Exception as e:
            raise WrongPassphrase(
                "Cannot decrypt embedding — wrong passphrase or corrupted "
                "data.") from e
