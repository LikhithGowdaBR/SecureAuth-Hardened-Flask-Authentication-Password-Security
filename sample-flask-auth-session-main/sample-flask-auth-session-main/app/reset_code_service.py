"""Short-lived, single-use reset-code service.

For a multi-worker deployment, back this store with Redis or a database.
"""

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app


class PasswordResetCodeService:
    def __init__(self):
        self.codes = {}
        self.code_expiry = timedelta(minutes=10)
        self.max_attempts = 5

    def _digest(self, email, code):
        key = current_app.config["SECRET_KEY"].encode("utf-8")
        return hmac.new(key, f"{email.casefold()}:{code}".encode("utf-8"), hashlib.sha256).hexdigest()

    def generate_code(self, email):
        code = f"{secrets.randbelow(1_000_000):06d}"
        self.codes[email.casefold()] = {
            "digest": self._digest(email, code),
            "expires_at": datetime.now(timezone.utc) + self.code_expiry,
            "attempts": 0,
        }
        return code

    def verify_code(self, email, code):
        record = self.codes.get(email.casefold())
        if not record or datetime.now(timezone.utc) >= record["expires_at"]:
            self.codes.pop(email.casefold(), None)
            return False
        if record["attempts"] >= self.max_attempts:
            self.codes.pop(email.casefold(), None)
            return False
        if not hmac.compare_digest(record["digest"], self._digest(email, code)):
            record["attempts"] += 1
            if record["attempts"] >= self.max_attempts:
                self.codes.pop(email.casefold(), None)
            return False
        self.codes.pop(email.casefold(), None)
        return True

    def cleanup_expired(self):
        now = datetime.now(timezone.utc)
        for email, record in list(self.codes.items()):
            if record["expires_at"] <= now:
                self.codes.pop(email, None)

    def discard_code(self, email):
        """Discard a code when delivery fails."""
        self.codes.pop(email.casefold(), None)
