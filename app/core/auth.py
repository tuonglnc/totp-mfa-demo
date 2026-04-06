"""
app/core/auth.py — Password Hashing with Argon2id

Argon2id is the OWASP-recommended algorithm for password hashing (2023).
It is the winner of the Password Hashing Competition and resists:
- GPU/ASIC brute-force (memory-hard)
- Side-channel timing attacks (constant-time compare)
- Both time-cost and memory-cost are configurable
"""

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError


# OWASP recommended Argon2id parameters (2023):
# - time_cost=2 (iterations)
# - memory_cost=19456 (19 MB)
# - parallelism=1
_ph = PasswordHasher(
    time_cost=2,
    memory_cost=19_456,   # KiB — ~19 MB
    parallelism=1,
    hash_len=32,
    salt_len=16,
)


def hash_password(password: str) -> str:
    """
    Hash a plaintext password using Argon2id.

    A random 128-bit salt is generated automatically by argon2-cffi.
    The returned string includes algorithm parameters, salt, and digest —
    it is self-contained and portable.

    Args:
        password: User's plaintext password.

    Returns:
        Argon2id hash string (e.g., "$argon2id$v=19$m=19456,t=2,p=1$...")
    """
    return _ph.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    """
    Verify a plaintext password against an Argon2id hash.

    Uses constant-time comparison internally to prevent timing attacks.
    If the stored hash uses outdated parameters, returns True but signals
    that the hash should be re-hashed (handled by check_needs_rehash).

    Args:
        password_hash: Stored Argon2id hash string.
        password: Plaintext password to verify.

    Returns:
        True if password matches, False otherwise.
    """
    try:
        return _ph.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def check_needs_rehash(password_hash: str) -> bool:
    """
    Check if a stored hash needs to be upgraded to current parameters.

    Call this after a successful login and re-hash + store if True.

    Args:
        password_hash: Stored Argon2id hash string.

    Returns:
        True if the hash should be re-computed with current parameters.
    """
    return _ph.check_needs_rehash(password_hash)
