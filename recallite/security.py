"""
recallite.security — password protection for memory (secure mode).

- Passwords are never stored in plain text: PBKDF2-HMAC-SHA256 with a
  random salt and 200,000 iterations, kept in a `settings` table.
- Lock state is per-session (in RAM). Restarting the app locks it again.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import sqlite3

_ITERATIONS = 200_000


def _hash_password(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                               salt, _ITERATIONS)


class SecurityManager:
    """Manages the password and the per-session lock for one user."""

    def __init__(self, db: sqlite3.Connection, user_id: str, secure: bool,
                 audit=None):
        self._db = db
        self.user_id = user_id
        self.secure = secure          # is secure mode configured on?
        self.unlocked = not secure    # session state; secure starts locked
        self._audit = audit or (lambda event, detail="": None)
        self._init_schema()

    def _init_schema(self) -> None:
        self._db.execute("""
            CREATE TABLE IF NOT EXISTS settings (
                user_id TEXT PRIMARY KEY,
                salt    BLOB NOT NULL,
                pw_hash BLOB NOT NULL
            )""")
        self._db.commit()

    # -- password lifecycle --------------------------------------------

    def has_password(self) -> bool:
        row = self._db.execute(
            "SELECT 1 FROM settings WHERE user_id = ?",
            (self.user_id,)).fetchone()
        return row is not None

    def set_password(self, password: str) -> None:
        if len(password) < 4:
            raise ValueError("Password must be at least 4 characters.")
        salt = os.urandom(16)
        self._db.execute(
            "INSERT OR REPLACE INTO settings (user_id, salt, pw_hash) "
            "VALUES (?, ?, ?)",
            (self.user_id, salt, _hash_password(password, salt)))
        self._db.commit()

    def verify_password(self, password: str) -> bool:
        row = self._db.execute(
            "SELECT salt, pw_hash FROM settings WHERE user_id = ?",
            (self.user_id,)).fetchone()
        if row is None:
            return False
        salt, stored = row
        return hmac.compare_digest(stored, _hash_password(password, salt))

    # -- lock / unlock --------------------------------------------------

    def enable(self, password: str) -> str:
        """Handle /enable. Sets the password on first use, verifies after."""
        if not self.secure:
            return "Secure mode is not turned on for this store."
        if not self.has_password():
            self.set_password(password)
            self.unlocked = True
            self._audit("auth.password_set", "first /enable set the password")
            return "Password set. Secure mode unlocked for this session."
        if self.verify_password(password):
            self.unlocked = True
            self._audit("auth.unlock", "")
            return "Correct password. Memory unlocked for this session."
        self._audit("auth.unlock_failed", "wrong password")
        return "Wrong password. Memory stays locked."

    def change_password(self, old: str, new: str) -> str:
        """Change the password (requires the current one)."""
        if not self.secure:
            return "Secure mode is not turned on for this store."
        if not self.has_password():
            return "No password set yet. Use /enable <password> to set one."
        if not self.verify_password(old):
            self._audit("auth.passwd_change_failed", "wrong current password")
            return "Current password is wrong. Password unchanged."
        try:
            self.set_password(new)
        except ValueError as e:
            return str(e)
        self.unlocked = True
        self._audit("auth.passwd_changed", "")
        return "Password changed. Secure mode unlocked for this session."

    def lock(self) -> str:
        if not self.secure:
            return "Secure mode is not turned on for this store."
        self.unlocked = False
        self._audit("auth.lock", "")
        return "Memory locked. Use /enable <password> to unlock."

    def check(self) -> bool:
        """True if memory operations are currently allowed."""
        return self.unlocked
