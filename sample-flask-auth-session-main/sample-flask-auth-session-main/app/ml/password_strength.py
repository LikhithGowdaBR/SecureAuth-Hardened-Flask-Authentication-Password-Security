"""Local AI-inspired password-risk classifier.

Model pickle files are intentionally not loaded at the authentication boundary:
pickle deserialization can execute code when the artifact is replaced.
"""

from dataclasses import dataclass
import math
import re

COMMON_PASSWORDS = {"password", "password1", "123456", "12345678", "qwerty", "letmein", "admin", "welcome", "iloveyou", "abc123", "monkey", "football"}
SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiop")


@dataclass(frozen=True)
class PasswordAssessment:
    score: int
    label: str
    feedback: str

    @property
    def accepted(self):
        return self.label == "strong"


def _has_sequence(value: str) -> bool:
    value = value.casefold()
    fragments = (value[index:index + 4] for index in range(len(value) - 3))
    return any(fragment in sequence for fragment in fragments for sequence in SEQUENCES)


def assess_password(password: str, username: str = "", email: str = "") -> PasswordAssessment:
    """Classify risk from entropy, composition, and known weak patterns."""
    password = password or ""
    lowered = password.casefold()
    personal_terms = {username.casefold(), email.partition("@")[0].casefold()}
    personal_terms = {term for term in personal_terms if len(term) >= 3}

    if lowered in COMMON_PASSWORDS or any(term in lowered for term in personal_terms):
        return PasswordAssessment(0, "weak", "Choose a password that does not contain common words or account details.")
    if len(password) < 12:
        return PasswordAssessment(1, "weak", "Use at least 12 characters.")
    if len(password.encode("utf-8")) > 72:
        return PasswordAssessment(1, "weak", "Use at most 72 UTF-8 bytes.")

    classes = sum(bool(re.search(pattern, password)) for pattern in (r"[a-z]", r"[A-Z]", r"\d", r"[^\w]"))
    charset = 26 * bool(re.search(r"[a-z]", password)) + 26 * bool(re.search(r"[A-Z]", password)) + 10 * bool(re.search(r"\d", password)) + 33 * bool(re.search(r"[^\w]", password))
    entropy = len(password) * math.log2(max(charset, 1))
    repeated = bool(re.search(r"(.)\1\1", password))
    sequence = _has_sequence(password)
    score = min(4, (1 if len(password) >= 16 else 0) + classes - int(repeated) - int(sequence))

    if classes < 3 or entropy < 50 or repeated or sequence:
        return PasswordAssessment(max(score, 1), "medium", "Use a longer, unique passphrase with more character variety and no predictable sequences.")
    return PasswordAssessment(max(score, 3), "strong", "Strong password.")


def predict_strength(password: str) -> int:
    """Backward-compatible 0/1/2 classifier result."""
    return {"weak": 0, "medium": 1, "strong": 2}[assess_password(password).label]
