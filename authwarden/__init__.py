"""authwarden — production-grade FastAPI authentication library.

    from authwarden import AuthWarden, WardenConfig
    from authwarden.storage.memory import MemoryUserStore

    warden = AuthWarden(config=WardenConfig(secret_key="..."), user_store=MemoryUserStore())
    app.include_router(warden.router, prefix="/auth", tags=["auth"])
"""
from authwarden.core.config import OAuthProviderConfig, WardenConfig
from authwarden.core.manager import AuthWarden
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

__version__ = "0.7.0"

__all__ = [
    "AuthWarden",
    "WardenConfig",
    "OAuthProviderConfig",
    "AuthError",
    "UserCreate",
    "UserRead",
    "UserInDB",
    "OAuthAccount",
    "OAuthAccountRead",
    "OAuthUserInfo",
    "TokenPair",
    "TokenPayload",
    "RefreshTokenRequest",
    "LogoutRequest",
    "AbstractUserStore",
    "MemoryUserStore",
]