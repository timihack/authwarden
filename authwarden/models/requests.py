"""Request and response schemas for authwarden's FastAPI routers.
 
UserCreate (models/user.py) is reused directly for registration.
Everything else needed by routes lives here to keep models/user.py
and models/token.py focused on the storage-facing schemas.
"""
from __future__ import annotations

from pydantic import BaseModel

from authwarden.models.user import UserRead


# ---- Verification ------------------------------------------------------
class VerifyEmailRequest(BaseModel):
  """POST /auth/verify-email - link-based verification."""
  token: str


class VerifyOtpRequest(BaseModel):
  """POST /auth/verify-otp - OTP-based verification."""
  identifier: str  # email or phone used at registration
  otp: str

class ResendVerificationRequest(BaseModel):
  """POST /auth/resend-verification."""
  identifier: str


# ---- Login -------------------------------------------------------------
class LoginRequest(BaseModel):
  """POST /auth/login.
  
  identifier is matched againt config.login_indetifier_fields in order
  (e.g. email, then username, then phone.)
  """
  identifier: str
  password: str
  totp_code: str | None = None


class TokenResponse(BaseModel):
  """Returned by /auth/login - token pair flattened alongside the user."""
  access_token: str
  refresh_token: str
  token_type: str = "bearer"
  user: UserRead


# ---- Password ---------------------------------------------------------
class ForgotPasswordRequest(BaseModel):
  """POST /auth/forgot-password."""
  identifier: str


class ResetPasswordRequest(BaseModel):
  """POST /auth/reset-password - link-based reset."""
  token: str
  new_password: str

class ResetPasswordOtpRequest(BaseModel):
  """POST /auth/reset-password-otp - OTP-based reset."""
  identifier: str
  otp: str
  new_password: str


class ChangePasswordRequest(BaseModel):
  """POST /auth/change-password (authenticated)"""
  current_password: str
  new_password: str


class SetPasswordRequest(BaseModel):
  """POST /auth/set-password (authenticated, OAuth-only accounts)."""
  new_password: str


# ── MFA ────────────────────────────────────────────────────────────────────
 
class MfaConfirmRequest(BaseModel):
  """POST /auth/mfa/confirm (authenticated)."""
  totp_code: str


class MfaDisableRequest(BaseModel):
  """POST /auth/mfa/disable (authenticated)."""
  password: str
  totp_or_backup_code: str


# ── OAuth ──────────────────────────────────────────────────────────────────

class OAuthAuthorizeResponse(BaseModel):
  """GET /auth/oauth/{provider}/authorize."""
  authorization_url: str


class OAuthCallbackRequest(BaseModel):
  """POST /auth/oauth/{provider}/callback."""
  code: str
  state: str
  post_body: dict | None = None  # Apple first-login name extraction only


class OAuthCallbackResponse(BaseModel):
  """Returned by /auth/oauth/{provider}/callback."""
  access_token: str
  refresh_token: str
  token_type: str = "bearer"
  user: UserRead
  is_new_user: bool


# ── Generic ────────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
  """Generic success message for fire-and-forget endpoints."""
  detail: str
