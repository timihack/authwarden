"""Pydantic v2 user models for authwarden.

UserInDB is the canonical storage model.
UserInDB is designed for extension:
 
    # Option 1 — extra_data dict
    user = UserInDB(email="a@b.com", extra_data={"company_id": "x"})
 
    # Option 2 — subclass with typed fields (recommended)
    class MyUser(UserInDB):
        company_id: str | None = None
        subscription_tier: str = "free"
 
    # Option 3 — extra="allow" accepts any kwargs
    user = UserInDB(email="a@b.com", company_id="x")
UserRead is the safe public projection (no secrets).
OAuthAccount tracks linked social login providers.
OAuthUserInfo is the normalized response from any OAuth provider.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import ConfigDict, BaseModel, EmailStr, Field


def _now() -> datetime: return datetime.now(timezone.utc)
def _uuid() -> str: return str(uuid.uuid4())


class UserBase(BaseModel):
    """Shared fields across user request/response schemas."""
    email: EmailStr
    username: str | None = None
    full_name: str | None = None


class UserCreate(UserBase):
    """Schema for the POST /auth/register request body."""
    password: str
    phone_number: str | None = None


class UserRead(UserBase):
    """Public-safe user representation returned by all API endpoints.

    Never includes hashed_password, MFA secrets, backup codes, or
    internal reset/verification state.
    Subclass to expose extra fields from your custom UserInDB::
 
    class MyUserRead(UserRead):
        company_id: str | None = None
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
    model_config = ConfigDict(from_attributes=True)


class UserInDB(UserBase):
    """Full user model as stored in the user store.

    Contains all sensitive fields. Never returned directly from the API —
    always projected through UserRead or a custom response schema.
    """
    model_config = ConfigDict(from_attributes=True, extra="allow")

    id: str = Field(default_factory=_uuid)
    hashed_password: str | None = None          # None for OAuth-only accounts

    # Phone — enables SMS verification and phone login
    phone_number: str | None = None
    phone_verified: bool = False

    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = Field(default_factory=list)
    scopes: list[str] = Field(default_factory=list)

    # Arbitrary metadata (alternative to sbuclassing for simple cases)
    extra_data: dict[str, Any] = Field(default_factory=dict)

    # MFA
    mfa_enabled: bool = False
    mfa_secret: str | None = None               # active TOTP secret (base32)
    mfa_pending_secret: str | None = None       # set during setup, before confirmation
    backup_codes: list[str] = Field(default_factory=list)  # stored as argon2 hashes

    # Email verification
    last_verification_sent_at: datetime | None = None

    # OTP verification (SMS or email)
    verification_otp_hash: str | None = None               # active OTP secret (base32)
    verification_otp_expires_at: datetime | None = None
    verification_otp_attempts: int = 0

    # Password reset — link-based
    last_reset_request_at: datetime | None = None
    reset_token_hash: str | None = None
    reset_token_used_at: datetime | None = None
 
    # Password reset — OTP-based
    reset_otp_hash: str | None = None
    reset_otp_expires_at: datetime | None = None
    reset_otp_attempts: int = 0

    # Brute force protection
    failed_login_attempts: int = 0
    locked_until: datetime | None = None
 
    created_at: datetime = Field(default_factory=_now)
    updated_at: datetime = Field(default_factory=_now)
 
    def to_read(self) -> UserRead:
        """Project to the public-safe UserRead.

        Override in subclasses to return a custom UserRead subclass::

            def to_read(self) -> MyUserRead:
                return MyUserRead(**super().to_read().model_dump(), company_id=self.company_id)
        """
        return UserRead(
            id=self.id, email=self.email, username=self.username,
            full_name=self.full_name, is_active=self.is_active,
            is_verified=self.is_verified, is_superuser=self.is_superuser,
            roles=self.roles, scopes=self.scopes, mfa_enabled=self.mfa_enabled,
            created_at=self.created_at, updated_at=self.updated_at,
        )


class OAuthAccount(BaseModel):
    """A linked OAuth provider account associated with a local user.

    provider_user_id is the authoritative link key — never trust email alone.
    Tokens are stored encrypted at rest (Fernet) and never exposed in responses.
    """
    model_config = ConfigDict(from_attributes=True)
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


class OAuthAccountRead(BaseModel):
    """Public-safe OAuth account representation (no tokens)."""
    model_config = ConfigDict(from_attributes=True)
    id: str
    provider: str
    email: str | None
    created_at: datetime


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