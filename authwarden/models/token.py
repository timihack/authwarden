"""Pydantic v2 token models for authwarden JWT flows."""
from __future__ import annotations

from pydantic import BaseModel


class TokenPayload(BaseModel):
    """Decoded JWT payload.

    Attributes:
        sub:    Subject — the user's UUID.
        jti:    JWT ID — UUID4 enabling per-token revocation.
        type:   Token type — ``"access"`` or ``"refresh"``.
        roles:  Role list embedded at issue time.
        scopes: OAuth-style permission scopes embedded at issue time.
        exp:    Expiry as a UTC Unix timestamp integer.
        iat:    Issued-at as a UTC Unix timestamp integer.
    """

    sub: str
    jti: str
    type: str
    roles: list[str] = []
    scopes: list[str] = []
    exp: int
    iat: int


class TokenPair(BaseModel):
    """Access + refresh token pair returned on login or token refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshTokenRequest(BaseModel):
    """Request body for POST /auth/refresh."""

    refresh_token: str


class LogoutRequest(BaseModel):
    """Request body for POST /auth/logout.

    refresh_token is optional — if provided it will also be blacklisted.
    """

    refresh_token: str | None = None