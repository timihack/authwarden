"""Pydantic v2 user models for authwarden.

UserInDB is the canonical storage model.
UserRead is the safe public projection (no secrets).
OAuthAccount tracks linked social login providers.
OAuthUserInfo is the normalized response from any OAuth provider.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from pydantic import BaseModel, EmailStr, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uuid() -> str:
    return str(uuid.uuid4())


class UserBase(BaseModel):
    """Shared fields across user request/response schemas."""

    email: EmailStr
    username: str | None = None
    full_name: str | None = None


class UserCreate(UserBase):
    """Schema for the POST /auth/register request body."""

    password: str


class UserRead(UserBase):
    """Public-safe user representation returned by all API endpoints.

    Never includes hashed_password, MFA secrets, backup codes, or
    internal reset/verification state.
    """

    id: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: list[str]
    scopes: list[str]
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class UserInDB(UserBase):
    """Full user model as stored in the user store.

    Contains all sensitive fields. Never returned directly from the API —
    always projected through UserRead or a custom response schema.
    """

    id: str = Field(default_factory=_uuid)
    hashed_password: str | None = None          # None for OAuth-only accounts

    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)

    # MFA
    mfa_enabled: bool = False
    mfa_secret: str | None = None               # active TOTP secret (base32)
    mfa_pending_secret: str | None = None       # set during setup, before confirmation
    backup_codes: list[str] = Field(default_factory=list)  # stored as argon2 hashes

    # Email verification
    last_verification_sent_at: datetime | None = None

    # Password reset
    last_reset_request_at: datetime | None = None
    reset_token_hash: str | None = None         # SHA-256 hex digest of raw token
    reset_token_used_at: datetime | None = None

    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    model_config = {"from_attributes": True}

    def to_read(self) -> UserRead:
        """Project this storage model into the public-safe UserRead schema."""
        return UserRead(
            id=self.id,
            email=self.email,
            username=self.username,
            full_name=self.full_name,
            is_active=self.is_active,
            is_verified=self.is_verified,
            is_superuser=self.is_superuser,
            roles=self.roles,
            scopes=self.scopes,
            mfa_enabled=self.mfa_enabled,
            created_at=self.created_at,
            updated_at=self.updated_at,
        )


class OAuthAccount(BaseModel):
    """A linked OAuth provider account associated with a local user.

    provider_user_id is the authoritative link key — never trust email alone.
    Tokens are stored encrypted at rest (Fernet) and never exposed in responses.
    """

    id: str = Field(default_factory=_uuid)
    user_id: str
    provider: str                               # "google", "github", "apple", etc.
    provider_user_id: str                       # provider's stable user ID
    email: str | None = None                    # provider email at time of linking
    access_token: str | None = None             # encrypted at rest
    refresh_token: str | None = None            # encrypted at rest
    token_expires_at: datetime | None = None
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)

    model_config = {"from_attributes": True}


class OAuthAccountRead(BaseModel):
    """Public-safe OAuth account representation (no tokens)."""

    id: str
    provider: str
    email: str | None
    created_at: datetime

    model_config = {"from_attributes": True}


class OAuthUserInfo(BaseModel):
    """Normalized user info returned by any OAuth provider callback.

    Every provider class maps its own response format into this schema
    before the account-linking logic runs.
    """

    provider: str
    provider_user_id: str
    email: str | None = None
    email_verified: bool = False
    full_name: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    avatar_url: str | None = None
    raw: dict = Field(default_factory=dict)     # full raw provider response