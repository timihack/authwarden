"""WardenConfig — central configuration for authwarden.

All settings can be provided via constructor keyword arguments or
automatically loaded from environment variables (pydantic-settings maps
UPPER_SNAKE_CASE env vars to field names).

Example::

  # Direct
  config = WardenConfig(secret_key="my-secret")

  # From environment
  # SECRET_KEY=my-secret python app.py
  config = WardenConfig()

  # From .env file (auto-loaded)
  config = WardenConfig()
"""
from __future__ import annotations

from typing import Literal

from pydantic import BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class OAuthProviderConfig(BaseModel):
  """Configuration for a single OAuth 2.0 / OIDC provider.

  Attributes:
      client_id:     OAuth application client ID.
      client_secret: OAuth application client secret.
                      For Apple, leave empty — the secret is generated
                      dynamically from apple_private_key_pem.
      redirect_uri:  Callback URL. Must match exactly what is registered
                      in the provider's developer console.
      scopes:        Override the provider's default scopes. Empty list
                      means use built-in provider defaults.
      enabled:       Set False to temporarily disable without removing config.
  """

  client_id: str
  client_secret: str
  redirect_uri: str
  scopes: list[str] = []
  enabled: bool = True


class WardenConfig(BaseSettings):
  """Top-level configuration object for AuthWarden.

  Loaded from environment variables, a ``.env`` file, or passed directly
  at instantiation. All env var names match field names in UPPER_SNAKE_CASE.
  """

  model_config = SettingsConfigDict(
      env_file=".env",
      env_file_encoding="utf-8",
      case_sensitive=False,
      extra="ignore",
  )

  # ── JWT ───────────────────────────────────────────────────────────────────
  secret_key: str
  algorithm: str = "HS256"
  access_token_ttl: int = 900          # seconds — 15 minutes
  refresh_token_ttl: int = 604800      # seconds — 7 days
  enable_refresh_rotation: bool = True

  # ── Passwords ─────────────────────────────────────────────────────────────
  password_hasher: Literal["argon2", "bcrypt"] = "argon2"
  min_password_length: int = 8
  require_password_uppercase: bool = False
  require_password_digit: bool = False
  require_password_special: bool = False

  # ---- brute-force protection ------------------------------------------------------
  max_failed_attempts: int = 5  # 0 = disable
  login_lockout_duration: int = 900   # seconds — 15 minutes
  max_otp_attempts: int = 5       # 0 = disable

  # ── Email ─────────────────────────────────────────────────────────────────
  email_backend: Literal["smtp", "console"] = "console"
  smtp_host: str = "localhost"
  smtp_port: int = 587
  smtp_username: str | None = None
  smtp_password: str | None = None
  smtp_use_tls: bool = True
  emails_from_name: str = "AuthWarden"
  emails_from_address: str = "noreply@example.com"

  # ---- SMS -----------------------------------------------------------------
  twilio_account_sid: str | None = None
  twilio_auth_token: str | None = None
  twilio_from_number: str | None = None
  aws_sns_region: str | None = None
  aws_sns_sender_id: str | None = None

  # ---- Login identifiers ---------------------------------------------------
  # Tried in order - first match wins
  # e.g ["email", "username", "phone"] tries email first, then username
  login_identifier_fields: list[Literal["email", "username", "phone"]] = ["email"]

  # ---- Verification --------------------------------------------------------
  verification_method: Literal["link", "otp"] = "link"
  verification_channels: list[Literal["email", "sms"]] = ["email"]
  otp_length: int = 6
  otp_ttl: int = 600 # 10 minutes

  # ---- Password Request ----------------------------------------------------
  password_reset_method: Literal["link", "otp"] = "link"
  password_reset_channels: list[Literal["email", "sms"]] = ["email"]

  # ── Token TTLs for flows ──────────────────────────────────────────────────
  email_verification_ttl: int = 86400     # 24 hours
  password_reset_ttl: int = 3600          # 1 hour
  resend_verification_cooldown: int = 60  # 1 minute rate limit

  # ── Registration ──────────────────────────────────────────────────────────
  require_email_verification: bool = True
  allow_registration: bool = True

  # ── Session ───────────────────────────────────────────────────────────────
  session_backend: Literal["memory", "redis"] | None = None
  redis_url: str | None = None

  # ── MFA ───────────────────────────────────────────────────────────────────
  enable_mfa: bool = False
  mfa_issuer_name: str = "AuthWarden"

  # ── OAuth ─────────────────────────────────────────────────────────────────
  oauth_providers: dict[str, OAuthProviderConfig] = {}
  auto_link_by_email: bool = True  # Case 2 account linking

  # Apple Sign In — required only when "apple" provider is configured
  apple_team_id: str | None = None
  apple_key_id: str | None = None
  apple_private_key_pem: str | None = None  # full contents of the .p8 file

  # ── Frontend URLs (used in email links) ───────────────────────────────────
  frontend_base_url: str = "http://localhost:3000"
  verify_email_path: str = "/auth/verify-email"
  reset_password_path: str = "/auth/reset-password"