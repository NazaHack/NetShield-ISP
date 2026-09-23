"""Password hashing and verification.

Argon2id is used rather than bcrypt: it is the current password-hashing
competition winner, it resists GPU and ASIC attack through its memory cost, and
the reference implementation handles salting and parameter encoding itself, so
there is no opportunity to get either wrong here.

The parameters are the ``argon2-cffi`` defaults, which track the RFC 9106
recommendations. They are deliberately not tuned down: a login is an infrequent
operation and the cost is what makes an offline attack on a stolen database
expensive.
"""

from __future__ import annotations

from typing import Final

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

#: Shortest password accepted. Length is the property that actually matters, so
#: it is required rather than a composition rule that pushes people towards
#: predictable substitutions.
MIN_PASSWORD_LENGTH: Final[int] = 12

#: Longest password accepted. Argon2 has no practical input limit, but bounding
#: it stops a multi-megabyte password from becoming a denial of service.
MAX_PASSWORD_LENGTH: Final[int] = 256

_hasher = PasswordHasher()

#: A valid Argon2 hash of a value no password will match.
#:
#: Verifying against this when an email is unknown makes a failed login cost the
#: same whether or not the account exists, which closes the timing side channel
#: that would otherwise let an attacker enumerate valid emails.
_DUMMY_HASH: Final[str] = _hasher.hash("netshield-nonexistent-account-placeholder")


class PasswordTooWeakError(ValueError):
    """Raised when a password does not meet the minimum requirements."""


def validate_password_strength(password: str) -> None:
    """Check a candidate password before it is hashed.

    Raises:
        PasswordTooWeakError: If the password is too short or too long.
    """
    if len(password) < MIN_PASSWORD_LENGTH:
        msg = f"Password must be at least {MIN_PASSWORD_LENGTH} characters."
        raise PasswordTooWeakError(msg)
    if len(password) > MAX_PASSWORD_LENGTH:
        msg = f"Password must be at most {MAX_PASSWORD_LENGTH} characters."
        raise PasswordTooWeakError(msg)


def hash_password(password: str) -> str:
    """Return an Argon2id hash of the password.

    Raises:
        PasswordTooWeakError: If the password fails the strength check.
    """
    validate_password_strength(password)
    return _hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    """Check a password against a stored hash in constant-ish time.

    Args:
        password: The candidate supplied at login.
        password_hash: The stored hash, or ``None`` when the account does not
            exist. A dummy verification runs in that case so the response time
            does not reveal whether the email is registered.

    Returns:
        Whether the password matches.
    """
    candidate = password_hash if password_hash is not None else _DUMMY_HASH
    try:
        _hasher.verify(candidate, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    return password_hash is not None


def needs_rehash(password_hash: str) -> bool:
    """Whether a stored hash was made with outdated parameters.

    Called after a successful login so that hashes are upgraded transparently
    when the cost parameters are raised.
    """
    try:
        return _hasher.check_needs_rehash(password_hash)
    except InvalidHashError:
        return True
