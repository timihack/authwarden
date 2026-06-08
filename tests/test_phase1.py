"""Phase 1 tests — foundation layer.

Covers: exceptions, models, config, storage (memory), utils.
No external services required — pure in-memory, no I/O.

Run:
  pytest tests/test_phase1.py -v
"""
from __future__ import annotations

import pytest
from datetime import datetime, timezone

from authwarden.exceptions import (
  AuthError,
  EmailAlreadyExists,
  WeakPassword,
  InvalidEmail,
  AlreadyVerified,
  RateLimited,
  InvalidCredentials,
  AccountInactive,
  EmailNotVerified,
  InvalidMFACode,
  MFARequired,
  InvalidToken,
  TokenExpired,
  TokenRevoked,
  TokenAlreadyUsed,
  SamePassword,
  PasswordNotSet,
  PasswordAlreadySet,
  UserNotFound,
  ForbiddenError,
  OAuthProviderNotConfigured,
  OAuthStateMismatch,
  OAuthCodeExchangeFailed,
  OAuthUserInfoFailed,
  EmailAlreadyRegistered,
  ProviderAlreadyLinked,
  LastLoginMethod,
)
from authwarden.models.user import (
  UserCreate,
  UserInDB,
  UserRead,
  OAuthAccount,
  OAuthUserInfo,
  OAuthAccountRead,
)
from authwarden.models.token import TokenPair, TokenPayload, RefreshTokenRequest, LogoutRequest
from authwarden.core.config import WardenConfig, OAuthProviderConfig
from authwarden.storage.base import AbstractUserStore
from authwarden.storage.memory import MemoryUserStore
from authwarden.utils import (
  utcnow,
  generate_jti,
  generate_secure_token,
  hash_token,
  verify_token_hash,
  generate_backup_codes,
  to_timestamp,
  seconds_until,
)


# ══════════════════════════════════════════════════════════════════
# EXCEPTIONS
# ══════════════════════════════════════════════════════════════════

class TestExceptions:
  def test_auth_error_base(self):
      """AuthError uses class-level detail by default."""
      err = AuthError()
      assert err.status_code == 400
      assert err.detail == "Authentication error"
      assert str(err) == "Authentication error"

  def test_auth_error_custom_detail(self):
      """AuthError accepts a custom detail string."""
      err = AuthError("something went wrong")
      assert err.detail == "something went wrong"

  def test_all_exceptions_inherit_auth_error(self):
      """Every exception is a subclass of AuthError."""
      subclasses = [
          EmailAlreadyExists, WeakPassword, InvalidEmail,
          AlreadyVerified, RateLimited, InvalidCredentials,
          AccountInactive, EmailNotVerified, InvalidMFACode,
          MFARequired, InvalidToken, TokenExpired, TokenRevoked,
          TokenAlreadyUsed, SamePassword, PasswordNotSet,
          PasswordAlreadySet, UserNotFound, ForbiddenError,
          OAuthProviderNotConfigured, OAuthStateMismatch,
          OAuthCodeExchangeFailed, OAuthUserInfoFailed,
          EmailAlreadyRegistered, ProviderAlreadyLinked, LastLoginMethod,
      ]
      for cls in subclasses:
          assert issubclass(cls, AuthError), f"{cls.__name__} must inherit AuthError"

  def test_status_codes(self):
      """Verify HTTP status codes on key exceptions."""
      assert EmailAlreadyExists().status_code == 409
      assert WeakPassword().status_code == 422
      assert InvalidCredentials().status_code == 401
      assert AccountInactive().status_code == 403
      assert RateLimited().status_code == 429
      assert TokenRevoked().status_code == 401
      assert ForbiddenError().status_code == 403
      assert OAuthStateMismatch().status_code == 400
      assert OAuthCodeExchangeFailed().status_code == 502
      assert LastLoginMethod().status_code == 400

  def test_exception_is_catchable_as_auth_error(self):
      """Subclasses can be caught as AuthError."""
      with pytest.raises(AuthError):
          raise InvalidCredentials()

  def test_exception_custom_detail_override(self):
      """Custom detail overrides the class default."""
      err = InvalidToken("token is missing the jti claim")
      assert err.detail == "token is missing the jti claim"


# ══════════════════════════════════════════════════════════════════
# MODELS — USER
# ══════════════════════════════════════════════════════════════════

class TestUserModels:
  def test_user_in_db_defaults(self):
      """UserInDB sets sensible defaults on creation."""
      user = UserInDB(email="alice@example.com")
      assert user.id is not None
      assert user.is_active is True
      assert user.is_verified is False
      assert user.is_superuser is False
      assert user.roles == []
      assert user.scopes == []
      assert user.mfa_enabled is False
      assert user.hashed_password is None

  def test_user_in_db_uuid_is_unique(self):
      """Each UserInDB gets a unique UUID."""
      u1 = UserInDB(email="a@example.com")
      u2 = UserInDB(email="b@example.com")
      assert u1.id != u2.id

  def test_user_in_db_to_read(self):
      """to_read() returns UserRead with no sensitive fields."""
      user = UserInDB(
          email="bob@example.com",
          hashed_password="secret-hash",
          full_name="Bob Smith",
          roles=["admin"],
          scopes=["read", "write"],
      )
      read = user.to_read()

      assert isinstance(read, UserRead)
      assert read.email == "bob@example.com"
      assert read.full_name == "Bob Smith"
      assert read.roles == ["admin"]
      assert read.scopes == ["read", "write"]
      assert not hasattr(read, "hashed_password")
      assert not hasattr(read, "mfa_secret")
      assert not hasattr(read, "backup_codes")

  def test_user_create_schema(self):
      """UserCreate requires email and password."""
      u = UserCreate(email="test@example.com", password="hunter2")
      assert u.email == "test@example.com"
      assert u.password == "hunter2"

  def test_user_invalid_email_rejected(self):
      """Pydantic rejects malformed email addresses."""
      with pytest.raises(Exception):
          UserCreate(email="not-an-email", password="pass")

  def test_user_timestamps_are_set(self):
      """created_at and updated_at default to current UTC time."""
      before = datetime.now(timezone.utc)
      user = UserInDB(email="ts@example.com")
      after = datetime.now(timezone.utc)
      assert before <= user.created_at <= after
      assert before <= user.updated_at <= after

  def test_oauth_account_defaults(self):
      """OAuthAccount sets a UUID and timestamps on creation."""
      acc = OAuthAccount(
          user_id="user-123",
          provider="google",
          provider_user_id="google-uid-456",
      )
      assert acc.id is not None
      assert acc.access_token is None
      assert acc.refresh_token is None

  def test_oauth_user_info_optional_fields(self):
      """OAuthUserInfo allows None email (e.g. Twitter)."""
      info = OAuthUserInfo(
          provider="twitter",
          provider_user_id="tw-123",
          email=None,
      )
      assert info.email is None
      assert info.email_verified is False
      assert info.raw == {}


# ══════════════════════════════════════════════════════════════════
# MODELS — TOKEN
# ══════════════════════════════════════════════════════════════════

class TestTokenModels:
  def test_token_pair_default_type(self):
      """TokenPair defaults token_type to bearer."""
      pair = TokenPair(access_token="aaa", refresh_token="bbb")
      assert pair.token_type == "bearer"

  def test_token_payload_fields(self):
      """TokenPayload stores all required JWT claims."""
      payload = TokenPayload(
          sub="user-id",
          jti="jti-value",
          type="access",
          roles=["admin"],
          scopes=["read"],
          exp=9999999999,
          iat=1000000000,
      )
      assert payload.sub == "user-id"
      assert payload.type == "access"
      assert "admin" in payload.roles

  def test_refresh_token_request(self):
      """RefreshTokenRequest wraps a single token string."""
      req = RefreshTokenRequest(refresh_token="mytoken")
      assert req.refresh_token == "mytoken"

  def test_logout_request_optional_refresh(self):
      """LogoutRequest allows refresh_token to be omitted."""
      req = LogoutRequest()
      assert req.refresh_token is None

      req_with = LogoutRequest(refresh_token="rt")
      assert req_with.refresh_token == "rt"


# ══════════════════════════════════════════════════════════════════
# CONFIG
# ══════════════════════════════════════════════════════════════════

class TestWardenConfig:
  def test_required_secret_key(self):
      """WardenConfig requires a secret_key."""
      config = WardenConfig(secret_key="my-secret")
      assert config.secret_key == "my-secret"

  def test_defaults(self):
      """WardenConfig applies sensible defaults."""
      config = WardenConfig(secret_key="s")
      assert config.algorithm == "HS256"
      assert config.access_token_ttl == 900
      assert config.refresh_token_ttl == 604800
      assert config.enable_refresh_rotation is True
      assert config.password_hasher == "argon2"
      assert config.min_password_length == 8
      assert config.email_backend == "console"
      assert config.require_email_verification is True
      assert config.allow_registration is True
      assert config.enable_mfa is False
      assert config.oauth_providers == {}
      assert config.auto_link_by_email is True

  def test_oauth_provider_config(self):
      """OAuthProviderConfig stores provider credentials."""
      provider = OAuthProviderConfig(
          client_id="cid",
          client_secret="csecret",
          redirect_uri="https://myapp.com/callback",
      )
      assert provider.enabled is True
      assert provider.scopes == []

  def test_oauth_provider_disabled(self):
      """OAuthProviderConfig can be disabled."""
      provider = OAuthProviderConfig(
          client_id="cid",
          client_secret="csecret",
          redirect_uri="https://myapp.com/callback",
          enabled=False,
      )
      assert provider.enabled is False

  def test_warden_config_with_oauth_providers(self):
      """WardenConfig stores multiple OAuth providers."""
      config = WardenConfig(
          secret_key="s",
          oauth_providers={
              "google": OAuthProviderConfig(
                  client_id="gid",
                  client_secret="gsecret",
                  redirect_uri="https://app.com/callback/google",
              )
          },
      )
      assert "google" in config.oauth_providers
      assert config.oauth_providers["google"].client_id == "gid"

  def test_apple_extras_default_none(self):
      """Apple-specific fields default to None."""
      config = WardenConfig(secret_key="s")
      assert config.apple_team_id is None
      assert config.apple_key_id is None
      assert config.apple_private_key_pem is None


# ══════════════════════════════════════════════════════════════════
# STORAGE — MEMORY
# ══════════════════════════════════════════════════════════════════

class TestMemoryUserStore:

  @pytest.fixture
  def store(self) -> MemoryUserStore:
      return MemoryUserStore()

  @pytest.fixture
  def sample_user(self) -> UserInDB:
      return UserInDB(email="alice@example.com", hashed_password="hashed")

  # ── Protocol satisfaction ──────────────────────────────────────

  def test_satisfies_abstract_protocol(self, store):
      """MemoryUserStore satisfies AbstractUserStore protocol."""
      assert isinstance(store, AbstractUserStore)

  # ── Create ────────────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_create_user(self, store, sample_user):
      created = await store.create(sample_user)
      assert created.id == sample_user.id
      assert store.user_count == 1

  @pytest.mark.asyncio
  async def test_create_increments_count(self, store):
      await store.create(UserInDB(email="a@example.com"))
      await store.create(UserInDB(email="b@example.com"))
      assert store.user_count == 2

  # ── Get by ID ─────────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_get_by_id_found(self, store, sample_user):
      await store.create(sample_user)
      found = await store.get_by_id(sample_user.id)
      assert found is not None
      assert found.id == sample_user.id

  @pytest.mark.asyncio
  async def test_get_by_id_not_found(self, store):
      result = await store.get_by_id("nonexistent-id")
      assert result is None

  # ── Get by email ──────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_get_by_email_found(self, store, sample_user):
      await store.create(sample_user)
      found = await store.get_by_email("alice@example.com")
      assert found is not None
      assert found.email == "alice@example.com"

  @pytest.mark.asyncio
  async def test_get_by_email_case_insensitive(self, store, sample_user):
      await store.create(sample_user)
      found = await store.get_by_email("ALICE@EXAMPLE.COM")
      assert found is not None

  @pytest.mark.asyncio
  async def test_get_by_email_not_found(self, store):
      result = await store.get_by_email("nobody@example.com")
      assert result is None

  # ── Update ────────────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_update_user(self, store, sample_user):
      await store.create(sample_user)
      sample_user.is_verified = True
      sample_user.roles = ["admin"]
      updated = await store.update(sample_user)
      assert updated.is_verified is True
      assert updated.roles == ["admin"]

  @pytest.mark.asyncio
  async def test_update_email_updates_index(self, store, sample_user):
      """Changing email updates the lookup index correctly."""
      await store.create(sample_user)
      old_email = sample_user.email
      sample_user.email = "new@example.com"
      await store.update(sample_user)

      assert await store.get_by_email(old_email) is None
      assert await store.get_by_email("new@example.com") is not None

  # ── Delete ────────────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_delete_user(self, store, sample_user):
      await store.create(sample_user)
      await store.delete(sample_user.id)
      assert await store.get_by_id(sample_user.id) is None
      assert await store.get_by_email(sample_user.email) is None
      assert store.user_count == 0

  @pytest.mark.asyncio
  async def test_delete_nonexistent_is_safe(self, store):
      """Deleting a non-existent user does not raise."""
      await store.delete("does-not-exist")  # should not raise

  # ── OAuth accounts ────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_create_and_get_oauth_account(self, store, sample_user):
      await store.create(sample_user)
      acc = OAuthAccount(
          user_id=sample_user.id,
          provider="google",
          provider_user_id="google-uid-999",
      )
      await store.create_oauth_account(acc)
      found = await store.get_oauth_account("google", "google-uid-999")
      assert found is not None
      assert found.user_id == sample_user.id

  @pytest.mark.asyncio
  async def test_get_oauth_account_not_found(self, store):
      result = await store.get_oauth_account("google", "unknown-uid")
      assert result is None

  @pytest.mark.asyncio
  async def test_get_oauth_accounts_for_user(self, store, sample_user):
      await store.create(sample_user)
      acc1 = OAuthAccount(user_id=sample_user.id, provider="google", provider_user_id="gid")
      acc2 = OAuthAccount(user_id=sample_user.id, provider="github", provider_user_id="ghid")
      await store.create_oauth_account(acc1)
      await store.create_oauth_account(acc2)

      accounts = await store.get_oauth_accounts_for_user(sample_user.id)
      assert len(accounts) == 2
      providers = {a.provider for a in accounts}
      assert providers == {"google", "github"}

  @pytest.mark.asyncio
  async def test_delete_oauth_account(self, store, sample_user):
      await store.create(sample_user)
      acc = OAuthAccount(
          user_id=sample_user.id,
          provider="github",
          provider_user_id="ghid-123",
      )
      await store.create_oauth_account(acc)
      await store.delete_oauth_account(sample_user.id, "github")
      result = await store.get_oauth_account("github", "ghid-123")
      assert result is None

  @pytest.mark.asyncio
  async def test_update_oauth_account(self, store, sample_user):
      await store.create(sample_user)
      acc = OAuthAccount(
          user_id=sample_user.id,
          provider="google",
          provider_user_id="gid",
      )
      await store.create_oauth_account(acc)
      acc.access_token = "new-token"
      updated = await store.update_oauth_account(acc)
      assert updated.access_token == "new-token"

  # ── Helpers ───────────────────────────────────────────────────

  def test_clear(self, store):
      """clear() resets all internal state."""
      store._users["x"] = UserInDB(email="x@example.com")
      store.clear()
      assert store.user_count == 0


# ══════════════════════════════════════════════════════════════════
# UTILS
# ══════════════════════════════════════════════════════════════════

class TestUtils:
  def test_utcnow_is_timezone_aware(self):
      """utcnow() returns a timezone-aware datetime."""
      now = utcnow()
      assert now.tzinfo is not None

  def test_generate_jti_is_uuid(self):
      """generate_jti() returns a valid UUID string."""
      import uuid
      jti = generate_jti()
      uuid.UUID(jti)  # raises ValueError if not valid UUID

  def test_generate_jti_is_unique(self):
      """generate_jti() returns a different value each time."""
      assert generate_jti() != generate_jti()

  def test_generate_secure_token_default_length(self):
      """generate_secure_token() returns a non-empty string."""
      token = generate_secure_token()
      assert isinstance(token, str)
      assert len(token) > 0

  def test_generate_secure_token_uniqueness(self):
      """Two tokens are never equal."""
      assert generate_secure_token() != generate_secure_token()

  def test_hash_token_is_deterministic(self):
      """hash_token() returns the same hash for the same input."""
      token = "my-reset-token"
      assert hash_token(token) == hash_token(token)

  def test_hash_token_hex_length(self):
      """SHA-256 hex output is exactly 64 characters."""
      assert len(hash_token("anything")) == 64

  def test_verify_token_hash_correct(self):
      """verify_token_hash() returns True for a matching token."""
      token = generate_secure_token()
      stored_hash = hash_token(token)
      assert verify_token_hash(token, stored_hash) is True

  def test_verify_token_hash_wrong(self):
      """verify_token_hash() returns False for a non-matching token."""
      token = generate_secure_token()
      stored_hash = hash_token(token)
      assert verify_token_hash("wrong-token", stored_hash) is False

  def test_generate_backup_codes_count_and_length(self):
      """generate_backup_codes() returns the right number and length."""
      codes = generate_backup_codes(count=8, length=8)
      assert len(codes) == 8
      assert all(len(c) == 8 for c in codes)

  def test_generate_backup_codes_unique(self):
      """Backup codes are all unique."""
      codes = generate_backup_codes(count=8)
      assert len(set(codes)) == 8

  def test_generate_backup_codes_unambiguous_alphabet(self):
      """Backup codes never contain 0, O, I, or 1."""
      codes = generate_backup_codes(count=20, length=20)
      all_chars = "".join(codes)
      for ambiguous in "0OI1":
          assert ambiguous not in all_chars

  def test_to_timestamp_returns_int(self):
      """to_timestamp() returns an integer Unix timestamp."""
      ts = to_timestamp(utcnow())
      assert isinstance(ts, int)

  def test_seconds_until_future(self):
      """seconds_until() returns a positive value for future datetimes."""
      from datetime import timedelta
      future = utcnow() + timedelta(seconds=60)
      secs = seconds_until(future)
      assert 58 <= secs <= 61

  def test_seconds_until_past_returns_zero(self):
      """seconds_until() returns 0 for past datetimes."""
      from datetime import timedelta
      past = utcnow() - timedelta(seconds=60)
      assert seconds_until(past) == 0