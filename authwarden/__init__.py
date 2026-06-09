"""authwarden — production-grade FastAPI authentication library.

Phase 1 exports: config, models, storage abstractions, exceptions.
AuthWarden facade will be exported here in Phase 6 (core/manager.py).
"""
from authwarden.core.config import OAuthProviderConfig, WardenConfig
from authwarden.exceptions import AuthError
from authwarden.models.token import LogoutRequest, RefreshTokenRequest, TokenPair, TokenPayload
from authwarden.models.user import (
    OAuthAccount,
    OAuthAccountRead,
    OAuthUserInfo,
    UserCreate,
    UserInDB,
    UserRead,
)
from authwarden.storage.base import AbstractUserStore
from authwarden.storage.memory import MemoryUserStore

__version__ = "0.1.0"

__all__ = [
    # Config
    "WardenConfig",
    "OAuthProviderConfig",
    # Exceptions
    "AuthError",
    # Models — user
    "UserCreate",
    "UserRead",
    "UserInDB",
    "OAuthAccount",
    "OAuthAccountRead",
    "OAuthUserInfo",
    # Models — token
    "TokenPair",
    "TokenPayload",
    "RefreshTokenRequest",
    "LogoutRequest",
    # Storage
    "AbstractUserStore",
    "MemoryUserStore",
]