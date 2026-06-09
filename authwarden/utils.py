"""Shared utility helpers for authwarden.
 
Covers secure token generation, time utilities, and token hashing.
All cryptographic operations delegate to the Python standard library.
Never implement custom crypto here — use proven primitives only.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timezone

def utcnow() -> datetime:
  """Return the current UTC time as a timezone-aware datetime."""
  return datetime.now(timezone.utc)


def generate_jti() -> str:
  """Generate a unique JWT ID (jti) using UUID4.
 
  Returns:
      A UUID4 string suitable for use as a JWT jti claim.
  """
  return str(uuid.uuid4())


def generate_secure_token(nbytes: int = 32) -> str:
  """Generate a cryptographically secure URL-safe token string.
 
    Args:
        nbytes: Number of random bytes. Output length ≈ 4/3 × nbytes
                due to base64 encoding.
 
    Returns:
        A URL-safe base64-encoded random string.
  """
  return secrets.token_urlsafe(nbytes)


def hash_token(token:str) -> str:
  """Return a hex-encoded SHA-256 hash of the given token.
 
    Used to store password-reset and email-verification tokens at rest
    without keeping the raw value in the database.
 
    Args:
        token: The plain-text token to hash.
 
    Returns:
        Lowercase hex string (64 characters)
  """
  return hashlib.sha256(token.encode()).hexdigest()


def verify_token_hash(token:str, token_hash:str) -> bool:
  """Constant-time comparison of a raw token against its stored hash.
 
    Prevents timing-based side-channel attacks when comparing tokens.
 
  Args:
        token:      The plain-text token submitted by the user.
        token_hash: The SHA-256 hex digest stored in the database.
 
  Returns:
        True if the token matches the stored hash, False otherwise.
  """
  expected = hash_token(token)
  return hmac.compare_digest(expected, token_hash)


def generate_backup_codes(count: int = 8, length: int = 8) -> list[str]:
  """Generate a list of random alphanumeric MFA backup codes.
 
    Uses an unambiguous alphabet (excludes 0/O/I/1) to prevent
    transcription errors.
 
  Args:
        count:  Number of codes to generate.
        length: Character length of each code.
 
  Returns:
        List of uppercase alphanumeric strings.
  """
  alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
  return [
        "".join(secrets.choice(alphabet) for _ in range(length))
        for _ in range(count)
    ]


def to_timestamp(dt: datetime) -> int:
  """Convert a datetime to a UTC Unix timestamp integer.
 
    Args:
        dt: A timezone-aware or naive (assumed UTC) datetime.
 
    Returns:
        Integer Unix timestamp.

  """
  if dt.tzinfo is None:
    dt = dt.replace(tzinfo=timezone.utc)
  return int(dt.timestamp())
  
 
def seconds_until(dt: datetime) -> int:
  """Return the number of seconds from now until the given datetime.
 
    Args:
        dt: A future timezone-aware datetime.
 
    Returns:
        Seconds remaining, or 0 if dt is already in the past.
  """
  delta = dt - utcnow()
  return max(0, int(delta.total_seconds()))