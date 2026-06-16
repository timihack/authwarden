"""Backup code management for MFA."""
from __future__ import annotations

from authwarden.authentication.password import PasswordHandler
from authwarden.models.user import UserInDB
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow


async def consume_backup_code(
    user: UserInDB,
    code: str,
    password_handler: PasswordHandler,
    store: AbstractUserStore,
) -> bool:
    """Attempt to consume a backup code.

    Iterates stored hashes, verifies using argon2, removes the matched
    hash (single-use), and persists the updated user.

    Args:
        user:             The user whose backup codes to check.
        code:             Plain-text backup code submitted by the user.
        password_handler: Used for argon2 verification.
        store:            User store to persist the consumed code removal.

    Returns:
        True if a code matched and was consumed, False otherwise.
    """
    for i, hashed in enumerate(user.backup_codes):
        if password_handler.verify_password(code, hashed):
            # Remove consumed code — single-use
            user.backup_codes = user.backup_codes[:i] + user.backup_codes[i+1:]
            user.updated_at = utcnow()
            await store.update(user)
            return True
    return False