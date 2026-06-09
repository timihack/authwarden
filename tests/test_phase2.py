"""Phase 2 tests — auth primitives.
 
Covers: PasswordHandler, JWTHandler, MemoryTokenBlacklist,
        SessionData, MemorySessionBackend.
 
RedisTokenBlacklist and RedisSessionBackend require a live Redis instance
and are not tested here — they have their own integration test suite.
 
Run:
    pytest tests/test_phase2.py -v
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest

from authwarden.authentication.jwt import (
  AbstractTokenBlacklist,
  JWTHandler,
  MemoryTokenBlacklist,
)
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import (
  InvalidToken,
  TokenExpired,
  TokenRevoked,
  WeakPassword,
)
from authwarden.models.token import TokenPair, TokenPayload
from authwarden.session.base import AbstractSessionBackend, SessionData
from authwarden.session.memory import MemorySessionBackend


# ---- Fixtures ---------------------------------------------------------------

@pytest.fixture
def config() -> WardenConfig:
  return WardenConfig(secret_key="my-super-secret-key-12345678901234567890")

@pytest.fixture
def strict_config() -> WardenConfig:
  """Config with all password policy rules enabled."""
  return WardenConfig(
    secret_key="test-secret",
    min_password_length=10,
    require_password_uppercase=True,
    require_password_digit=True,
    require_password_special=True,
  )

@pytest.fixture
def password_handler(config) -> PasswordHandler:
  return PasswordHandler(config)

@pytest.fixture
def jwt_handler(config) -> JWTHandler:
  return JWTHandler(config)

@pytest.fixture
def session_backend() -> MemorySessionBackend:
  return MemorySessionBackend()

def make_expired_token(secret: str, algorithm: str = "HS256", token_type: str = "access") -> str:
  """Create a token with an exp in the past for testing expiry handling."""
  payload = {
    "sub": "user-id",
    "jti": "test-jti-expired",
    "type": token_type,
    "roles": [],
    "scopes": [],
    "iat": 1000000000,
    "exp": 1000000001,  # far in the past
  }

  return pyjwt.encode(payload, secret, algorithm=algorithm)

def make_future_session(user_id: str = "user-1", days: int = 7) -> SessionData:
  return SessionData(
      user_id=user_id,
      expires_at=datetime.now(timezone.utc) + timedelta(days=days),
  )


def make_expired_session(user_id: str = "user-1") -> SessionData:
  return SessionData(
      user_id=user_id,
      expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
  )


  # ══════════════════════════════════════════════════════════════════
# PASSWORD HANDLER
# ══════════════════════════════════════════════════════════════════
 
class TestPasswordHandler:
  def test_hash_returns_string(self, password_handler):
    hashed = password_handler.hash_password("hunter2")
    assert isinstance(hashed, str)
    assert len(hashed) > 0

  def test_hash_is_not_plaintext(self, password_handler):
    hashed = password_handler.hash_password("hunter2")
    assert hashed != "hunter2"

  def test_hash_is_unique(self, password_handler):
    """Same password hashed twice produces different output (salted)."""
    h1 = password_handler.hash_password("hunter2")
    h2 = password_handler.hash_password("hunter2")
    assert h1 != h2

  def test_verify_correct_password(self, password_handler):
    hashed = password_handler.hash_password("correct-horse")
    assert password_handler.verify_password("correct-horse", hashed) is True

  def test_verify_wrong_password(self, password_handler):
    hashed = password_handler.hash_password("correct-horse")
    assert password_handler.verify_password("wrong-horse", hashed) is False

  def test_verify_empty_password(self, password_handler):
    hashed = password_handler.hash_password("something")
    assert password_handler.verify_password("", hashed) is False

  def test_verify_and_update_valid_no_rehash(self, password_handler):
    """verify_and_update returns (True, None) for a current-algorithm hash."""
    hashed = password_handler.hash_password("password")
    ok, new_hash = password_handler.verify_and_update("password", hashed)
    assert ok is True
    assert new_hash is None

  def test_verify_and_update_wrong_password(self, password_handler):
    """verify_and_update returns (False, None) for wrong password."""
    hashed = password_handler.hash_password("correct")
    ok, new_hash = password_handler.verify_and_update("wrong", hashed)
    assert ok is False
    assert new_hash is None

  def test_bcrypt_handler(self, config):
    """bcrypt hasher hashes and verifies correctly."""
    bcrypt_config = WardenConfig(secret_key="s", password_hasher="bcrypt")
    handler = PasswordHandler(bcrypt_config)
    hashed = handler.hash_password("bcrypt-test")
    assert handler.verify_password("bcrypt-test", hashed) is True
    assert handler.verify_password("wrong", hashed) is False

  # ── Policy ────────────────────────────────────────────────────
 
  def test_policy_passes_for_valid_password(self, password_handler):
    """Default policy (min 8 chars) passes for a long enough password."""
    password_handler.check_policy("longpassword")  # no exception

  def test_policy_rejects_too_short(self, password_handler):
    with pytest.raises(WeakPassword) as exc_info:
        password_handler.check_policy("short")
    assert "8 characters" in exc_info.value.detail

  def test_policy_rejects_missing_uppercase(self, strict_config):
    handler = PasswordHandler(strict_config)
    with pytest.raises(WeakPassword) as exc_info:
        handler.check_policy("lowercase123!")
    assert "uppercase" in exc_info.value.detail

  def test_policy_rejects_missing_digit(self, strict_config):
    handler = PasswordHandler(strict_config)
    with pytest.raises(WeakPassword) as exc_info:
        handler.check_policy("NoDigitsHere!")
    assert "digit" in exc_info.value.detail

  def test_policy_rejects_missing_special(self, strict_config):
    handler = PasswordHandler(strict_config)
    with pytest.raises(WeakPassword) as exc_info:
        handler.check_policy("NoSpecial123A")
    assert "special" in exc_info.value.detail

  def test_policy_error_lists_all_violations(self, strict_config):
    """A password violating multiple rules lists all of them."""
    handler = PasswordHandler(strict_config)
    with pytest.raises(WeakPassword) as exc_info:
        handler.check_policy("short")  # too short, no upper, no digit, no special
    detail = exc_info.value.detail
    assert "characters" in detail
    assert "uppercase" in detail
    assert "digit" in detail
    assert "special" in detail

  def test_policy_passes_strict_when_all_met(self, strict_config):
    handler = PasswordHandler(strict_config)
    handler.check_policy("ValidPass1!")  # no exception

 
# ══════════════════════════════════════════════════════════════════
# MEMORY TOKEN BLACKLIST
# ══════════════════════════════════════════════════════════════════

class TestMemoryTokenBlacklist:
  @pytest.mark.asyncio
  async def test_add_and_contains(self):
      bl = MemoryTokenBlacklist()
      await bl.add("jti-1", 60)
      assert await bl.contains("jti-1") is True

  @pytest.mark.asyncio
  async def test_not_contains_unknown_jti(self):
      bl = MemoryTokenBlacklist()
      assert await bl.contains("not-there") is False

  @pytest.mark.asyncio
  async def test_expired_entry_returns_false(self):
      """Entries past their TTL are evicted and return False."""
      bl = MemoryTokenBlacklist()
      await bl.add("jti-expired", 0)
      # TTL of 0 means it expires immediately; force the timestamp into past
      bl._store["jti-expired"] = time.time() - 1
      assert await bl.contains("jti-expired") is False

  @pytest.mark.asyncio
  async def test_clear_empties_store(self):
      bl = MemoryTokenBlacklist()
      await bl.add("jti-a", 60)
      await bl.add("jti-b", 60)
      bl.clear()
      assert bl.size == 0

  def test_satisfies_abstract_protocol(self):
      assert isinstance(MemoryTokenBlacklist(), AbstractTokenBlacklist)


# ══════════════════════════════════════════════════════════════════
# JWT HANDLER
# ══════════════════════════════════════════════════════════════════

class TestJWTHandler:

  # ── Token creation ────────────────────────────────────────────

  def test_create_access_token_returns_string(self, jwt_handler):
      token = jwt_handler.create_access_token("user-1")
      assert isinstance(token, str)
      assert len(token) > 0

  def test_create_refresh_token_returns_string(self, jwt_handler):
      token = jwt_handler.create_refresh_token("user-1")
      assert isinstance(token, str)

  def test_create_token_pair_returns_token_pair(self, jwt_handler):
      pair = jwt_handler.create_token_pair("user-1")
      assert isinstance(pair, TokenPair)
      assert pair.access_token != pair.refresh_token
      assert pair.token_type == "bearer"

  def test_tokens_are_unique(self, jwt_handler):
      """Two calls produce different tokens (unique jti)."""
      t1 = jwt_handler.create_access_token("user-1")
      t2 = jwt_handler.create_access_token("user-1")
      assert t1 != t2

  def test_roles_and_scopes_embedded(self, jwt_handler):
      token = jwt_handler.create_access_token(
          "user-1", roles=["admin"], scopes=["write"]
      )
      payload = jwt_handler.decode_token(token)
      assert "admin" in payload.roles
      assert "write" in payload.scopes

  # ── Decoding ──────────────────────────────────────────────────

  def test_decode_access_token(self, jwt_handler):
      token = jwt_handler.create_access_token("user-42")
      payload = jwt_handler.decode_token(token, expected_type="access")
      assert payload.sub == "user-42"
      assert payload.type == "access"
      assert payload.jti is not None

  def test_decode_refresh_token(self, jwt_handler):
      token = jwt_handler.create_refresh_token("user-42")
      payload = jwt_handler.decode_token(token, expected_type="refresh")
      assert payload.sub == "user-42"
      assert payload.type == "refresh"

  def test_decode_wrong_type_raises_invalid_token(self, jwt_handler):
      """Decoding a refresh token as 'access' raises InvalidToken."""
      refresh_token = jwt_handler.create_refresh_token("user-1")
      with pytest.raises(InvalidToken):
          jwt_handler.decode_token(refresh_token, expected_type="access")

  def test_decode_wrong_secret_raises_invalid_token(self, jwt_handler, config):
      token = jwt_handler.create_access_token("user-1")
      other_handler = JWTHandler(WardenConfig(secret_key="wrong-secret-key-1234567890123456"))
      with pytest.raises(InvalidToken):
          other_handler.decode_token(token)

  def test_decode_expired_token_raises_token_expired(self, config):
      expired = make_expired_token(config.secret_key)
      handler = JWTHandler(config)
      with pytest.raises(TokenExpired):
          handler.decode_token(expired)

  def test_decode_garbage_raises_invalid_token(self, jwt_handler):
      with pytest.raises(InvalidToken):
          jwt_handler.decode_token("not.a.token")

  def test_decode_empty_string_raises_invalid_token(self, jwt_handler):
      with pytest.raises(InvalidToken):
          jwt_handler.decode_token("")

  # ── Blacklist ─────────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_blacklist_jti(self, jwt_handler):
      await jwt_handler.blacklist_jti("some-jti", 60)
      assert await jwt_handler.is_blacklisted("some-jti") is True

  @pytest.mark.asyncio
  async def test_is_blacklisted_false_for_unknown(self, jwt_handler):
      assert await jwt_handler.is_blacklisted("unknown-jti") is False

  @pytest.mark.asyncio
  async def test_blacklist_token(self, jwt_handler):
      """blacklist_token() extracts jti and blacklists it."""
      token = jwt_handler.create_access_token("user-1")
      payload = jwt_handler.decode_token(token)
      await jwt_handler.blacklist_token(token)
      assert await jwt_handler.is_blacklisted(payload.jti) is True

  @pytest.mark.asyncio
  async def test_blacklist_token_expired_raises(self, config):
      """Blacklisting an already-expired token raises TokenExpired."""
      handler = JWTHandler(config)
      expired = make_expired_token(config.secret_key)
      with pytest.raises(TokenExpired):
          await handler.blacklist_token(expired)

  # ── verify_token ──────────────────────────────────────────────

  @pytest.mark.asyncio
  async def test_verify_token_valid(self, jwt_handler):
      token = jwt_handler.create_access_token("user-1", roles=["user"])
      payload = await jwt_handler.verify_token(token)
      assert payload.sub == "user-1"
      assert "user" in payload.roles

  @pytest.mark.asyncio
  async def test_verify_token_revoked_raises(self, jwt_handler):
      token = jwt_handler.create_access_token("user-1")
      await jwt_handler.blacklist_token(token)
      with pytest.raises(TokenRevoked):
          await jwt_handler.verify_token(token)

  @pytest.mark.asyncio
  async def test_verify_token_expired_raises(self, config):
      handler = JWTHandler(config)
      expired = make_expired_token(config.secret_key)
      with pytest.raises(TokenExpired):
          await handler.verify_token(expired)

  @pytest.mark.asyncio
  async def test_verify_refresh_token(self, jwt_handler):
      token = jwt_handler.create_refresh_token("user-1")
      payload = await jwt_handler.verify_token(token, expected_type="refresh")
      assert payload.type == "refresh"

  @pytest.mark.asyncio
  async def test_blacklist_does_not_affect_different_jti(self, jwt_handler):
      """Blacklisting one token does not affect a different token."""
      token_a = jwt_handler.create_access_token("user-1")
      token_b = jwt_handler.create_access_token("user-1")
      await jwt_handler.blacklist_token(token_a)
      payload = await jwt_handler.verify_token(token_b)
      assert payload is not None


# ══════════════════════════════════════════════════════════════════
# SESSION — BASE MODEL
# ══════════════════════════════════════════════════════════════════

class TestSessionData:
  def test_session_data_defaults(self):
      session = make_future_session()
      assert session.session_id is not None
      assert session.user_agent is None
      assert session.ip_hash is None

  def test_session_data_unique_ids(self):
      s1 = make_future_session()
      s2 = make_future_session()
      assert s1.session_id != s2.session_id

  def test_session_data_with_metadata(self):
      session = SessionData(
          user_id="u1",
          user_agent="Mozilla/5.0",
          ip_hash="abc123",
          expires_at=datetime.now(timezone.utc) + timedelta(days=1),
      )
      assert session.user_agent == "Mozilla/5.0"
      assert session.ip_hash == "abc123"


# ══════════════════════════════════════════════════════════════════
# SESSION — MEMORY BACKEND
# ══════════════════════════════════════════════════════════════════

class TestMemorySessionBackend:

  def test_satisfies_abstract_protocol(self, session_backend):
      assert isinstance(session_backend, AbstractSessionBackend)

  @pytest.mark.asyncio
  async def test_create_and_get(self, session_backend):
      session = make_future_session()
      await session_backend.create(session)
      found = await session_backend.get(session.session_id)
      assert found is not None
      assert found.session_id == session.session_id

  @pytest.mark.asyncio
  async def test_get_returns_none_for_unknown(self, session_backend):
      result = await session_backend.get("nonexistent-id")
      assert result is None

  @pytest.mark.asyncio
  async def test_get_expired_session_returns_none(self, session_backend):
      """Expired sessions are evicted and return None."""
      session = make_expired_session()
      session_backend._sessions[session.session_id] = session
      result = await session_backend.get(session.session_id)
      assert result is None

  @pytest.mark.asyncio
  async def test_delete_session(self, session_backend):
      session = make_future_session()
      await session_backend.create(session)
      await session_backend.delete(session.session_id)
      assert await session_backend.get(session.session_id) is None

  @pytest.mark.asyncio
  async def test_delete_nonexistent_is_safe(self, session_backend):
      await session_backend.delete("does-not-exist")  # no exception

  @pytest.mark.asyncio
  async def test_delete_all_for_user(self, session_backend):
      s1 = make_future_session("user-A")
      s2 = make_future_session("user-A")
      s3 = make_future_session("user-B")
      await session_backend.create(s1)
      await session_backend.create(s2)
      await session_backend.create(s3)

      await session_backend.delete_all_for_user("user-A")

      assert await session_backend.get(s1.session_id) is None
      assert await session_backend.get(s2.session_id) is None
      assert await session_backend.get(s3.session_id) is not None

  @pytest.mark.asyncio
  async def test_get_all_for_user(self, session_backend):
      s1 = make_future_session("user-X")
      s2 = make_future_session("user-X")
      s3 = make_future_session("user-Y")
      await session_backend.create(s1)
      await session_backend.create(s2)
      await session_backend.create(s3)

      results = await session_backend.get_all_for_user("user-X")
      assert len(results) == 2
      ids = {s.session_id for s in results}
      assert s1.session_id in ids
      assert s2.session_id in ids

  @pytest.mark.asyncio
  async def test_get_all_excludes_expired(self, session_backend):
      """Expired sessions are not returned by get_all_for_user."""
      active = make_future_session("user-Z")
      expired = make_expired_session("user-Z")
      await session_backend.create(active)
      session_backend._sessions[expired.session_id] = expired

      results = await session_backend.get_all_for_user("user-Z")
      assert len(results) == 1
      assert results[0].session_id == active.session_id

  def test_clear(self, session_backend):
      session_backend._sessions["x"] = make_future_session()
      session_backend.clear()
      assert session_backend.session_count == 0