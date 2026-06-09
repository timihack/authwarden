"""Password hashing and policy enforcement for authwarden.

Delegates entirely to pwdlib - never implements custom hashing.
Support argon2 (default) and bcrypt, selectable via WardenConfig.
"""
from __future__ import annotations

import re
from typing import Literal

from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher
from pwdlib.hashers.bcrypt import BcryptHasher

from authwarden.core.config import WardenConfig
from authwarden.exceptions import WeakPassword

def _build_hasher(hasher_type: Literal["argon2", "bcrypt"]) -> PasswordHash:
  """Instatiate a PasswordHase for the given algorithm."""
  if hasher_type == "argon2":
    return PasswordHash((Argon2Hasher(),))
  return PasswordHash((BcryptHasher(),))


class PasswordHandler:
  """Wraps pwdlib for hashing, verification, and policy enforcement.

  Usage::

      handler = PasswordHandler(config)
      hashed = handler.hash_password("hunter2")

      # On login — verify and silently rehash if needed:
      ok, new_hash = handler.verify_and_update("hunter2", hashed)
      if not ok:
          raise InvalidCredentials()
      if new_hash:
          user.hashed_password = new_hash  # store the upgraded hash
  """

  def __init__(self, config: WardenConfig) -> None:
    """Initialise with the given WardenConfig.

    Args:
        config: Determines which hasher to use and the password policy rules.
    """
    self._config = config
    self._hasher = _build_hasher(config.password_hasher)


  def hash_password(self, password: str) -> str:
     """Hash a plain-text password.
 
      Args:
          password: The plain-text password to hash.

      Returns:
          A hashed password string (argon2 or bcrypt PHC format).
      """
     return self._hasher.hash(password)
  

  def verify_password(self, plain: str, hashed: str) -> bool:
    """Verify a plain-text password against a stored hash.

    For login flows prefer verify_and_update() which also handles rehashing.

    Args:
        plain:  The plain-text candidate password.
        hashed: The stored hash to compare against.

    Returns:
        True if the password matches, False otherwise.
    """
    return self._hasher.verify(plain, hashed)

  
  def verify_and_update(self, plain: str, hashed: str) -> tuple[bool, str | None]:
    """Verify a password and return a fresh hash if the stored one needs upgrading.

    This is the preferred method to call on login — it combines
    verification and rehash detection in a single call.

    Args:
        plain:  The plain-text candidate password.
        hashed: The stored hash to verify against.

    Returns:
        A tuple of ``(is_valid, new_hash)``.
        ``new_hash`` is a fresh hash string when the stored hash needs
        upgrading (outdated algorithm or cost factor), or ``None`` if
        the stored hash is already up-to-date.
        When ``is_valid`` is False, ``new_hash`` is always ``None``.

    Example::

        ok, new_hash = handler.verify_and_update(plain, user.hashed_password)
        if not ok:
            raise InvalidCredentials()
        if new_hash:
            user.hashed_password = new_hash
            await store.update(user)
    """
    return self._hasher.verify_and_update(plain, hashed)
  
  def check_policy(self, password: str) -> None:
    """Validate a password against the configured policy rules.

    Always call this before hashing a new or changed password.

    Args:
        password: The plain-text password to validate.

    Raises:
        WeakPassword: If the password violates one or more policy rules,
                      with a message listing all violations.
    """
    errors: list[str] = []

    if len(password) < self._config.min_password_length:
        errors.append(
            f"at least {self._config.min_password_length} characters"
        )
    if self._config.require_password_uppercase and not re.search(r"[A-Z]", password):
        errors.append("at least one uppercase letter")
    if self._config.require_password_digit and not re.search(r"\d", password):
        errors.append("at least one digit")
    if self._config.require_password_special and not re.search(r"[^a-zA-Z0-9]", password):
        errors.append("at least one special character")

    if errors:
        raise WeakPassword("Password must contain: " + ", ".join(errors))
 