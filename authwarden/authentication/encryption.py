"""Symmetric encryption for OAuth tokens at rest.

Uses Fernet (AES128-CBC + HMAC) from the cryptography package.
The Fernet key is deterministically derived from WardenConfig.secret_key
via SHA-256, so no separate key management is required.
"""
from __future__ import annotations
import base64
import hashlib
from cryptography.fernet import Fernet, InvalidToken as FernetInvalidToken


def _derive_fernet_key(secret_key: str) -> bytes:
    """Derive a valid 32-byte url-safe base64 Fernet key from the app secret."""
    digest = hashlib.sha256(secret_key.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_token(value: str, secret_key: str) -> str:
    """Encrypt a token string for at-rest storage.

    Args:
        value:      Plain-text token (e.g. OAuth access_token).
        secret_key: WardenConfig.secret_key — used to derive the encryption key.

    Returns:
        Encrypted ciphertext as a string, safe to store in the database.
    """
    f = Fernet(_derive_fernet_key(secret_key))
    return f.encrypt(value.encode()).decode()


def decrypt_token(ciphertext: str, secret_key: str) -> str:
    """Decrypt a previously encrypted token.

    Args:
        ciphertext: The encrypted string returned by encrypt_token().
        secret_key: The same secret_key used to encrypt.

    Returns:
        The original plain-text token.

    Raises:
        cryptography.fernet.InvalidToken: If decryption fails (wrong key or tampered data).
    """
    f = Fernet(_derive_fernet_key(secret_key))
    return f.decrypt(ciphertext.encode()).decode()