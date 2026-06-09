"""JWT access and refresh token management for authwarden.
 
Wraps PyJWT — never implements custom signing or verification.
Provides a pluggable token blacklist with in-memory and Redis backends.
"""
from __future__ import annotations

import time
from typing import Protocol, runtime_checkable

import jwt as pyjwt
from jwt import ExpiredSignatureError, InvalidTokenError

from authwarden.core.config import WardenConfig
from authwarden.exceptions import InvalidToken, TokenExpired, TokenRevoked
from authwarden.models.token import TokenPair, TokenPayload
from authwarden.utils import generate_jti, to_timestamp, utcnow


# ---- Token Blacklist ----------------------------------------------------------

@runtime_checkable
class AbstractTokenBlacklist(Protocol): # Protocol defines a contract that other classes must satisfy
  """Protocol for token blacklisting.
  Implementations must be async-safe and handle their own TTL expiry.
  """

  async def add(self, jti: str, ttl_seconds: int) -> None:
      """Add a jti to the blacklist.

      Args:
          jti:         The JWT ID to blacklist.
          ttl_seconds: How long to retain the entry. Should match
                        the remaining lifetime of the token.
      """
      ...

  async def contains(self, jti: str) -> bool:
      """Return True if the jti is currently blacklisted.

      Args:
          jti: The JWT ID to check.

      Returns:
          True if blacklisted and not yet expired, False otherwise.
      """
      ...



class MemoryTokenBlacklist:
  """In-memory token blacklist backed by a plain dict.

  Entries are lazily cleaned up when they are checked past their TTL.
  Not suitable for multi-process deployments — use RedisTokenBlacklist instead.
  """

  def __init__(self) -> None:
     self._store: dict[str, float] = {}  # jti -> unix expiry timestamp

  async def add(self, jti: str, ttl_seconds: int) -> None:
     """Blacklist a jti for the given number of seconds."""
     self._store[jti] = time.time() + ttl_seconds

  async def contains(self, jti: str) -> bool:
     """Return True if the jti is blacklisted and has not expired"""
     expiry = self._store.get(jti)
     if expiry is None:
        return False
     if time.time() > expiry:
        del self._store[jti]
        return False
     return True
  
  def clear(self) -> None:
    """Remove all entries - useful between test cases."""
    self._store.clear()

  @property
  def size(self) -> int:
     """Return the number of active blacklist entries."""
     return len(self._store)


class RedisTokenBlacklist:
  """Redis-backed token blacklist using native key expiry.

  Requires the ``redis`` optional dependency::

      pip install authwarden[redis]

  Args:
      redis_client: An initialised ``redis.asyncio`` client instance.
  """

  _KEY_PREFIX = "authwarden:blacklist:"

  def __init__(self, redis_client) -> None:  # noqa: ANN001
      self._redis = redis_client

  async def add(self, jti: str, ttl_seconds: int) -> None:
      """Store a blacklisted jti in Redis with automatic expiry."""
      await self._redis.setex(
          f"{self._KEY_PREFIX}{jti}",
          max(1, ttl_seconds),
          "1",
      )

  async def contains(self, jti: str) -> bool:
      """Return True if the Redis key exists (not yet expired)."""
      result = await self._redis.exists(f"{self._KEY_PREFIX}{jti}")
      return bool(result)


  # ── JWT Handler ───────────────────────────────────────────────────────────────

class JWTHandler:
  """Issues, decodes, and revokes JWT access and refresh tokens.

  All token signing/verification is delegated to PyJWT. The handler
  manages token creation, type enforcement, and jti-based revocation.

  Usage::

      handler = JWTHandler(config)
      pair = handler.create_token_pair("user-uuid", roles=["admin"])
      payload = await handler.verify_token(pair.access_token)
  """

  def __init__(
      self,
      config: WardenConfig,
      blacklist: AbstractTokenBlacklist | None = None,
  ) -> None:
    """Initialise the JWT handler.

    Args:
        config:    WardenConfig — provides secret_key, algorithm, TTLs.
        blacklist: Blacklist backend. Defaults to MemoryTokenBlacklist.
    """
    self._config = config
    self._blacklist: AbstractTokenBlacklist = blacklist or MemoryTokenBlacklist()

  def _build_payload(
        self,
        user_id: str,
        token_type: str,
        roles: list[str],
        scopes: list[str],
        ttl: int,
  ) -> dict:
     """Build a raw JWT payload dict."""
     now = to_timestamp(utcnow())
     return {
        "sub": user_id,
        "jti": generate_jti(),
        "type": token_type,
        "roles": roles,
        "scopes": scopes,
        "iat": now,
        "exp": now + ttl,
     }
  
  def create_access_token(
        self,
        user_id: str,
        roles: list[str] | None = None,
        scopes: list[str] | None = None,
  ) -> str:
    """Issue a signed JWT access token.
     
    Args:
        user_id: The user's UUID — stored as the ``sub`` claim.
        roles:   Roles to embed in the payload.
        scopes:  Scopes to embed in the payload.

    Returns:
        A signed JWT string (type ``"access"``).
    """
    payload = self._build_payload(
        user_id=user_id,
        token_type="access",
        roles=roles or [],
        scopes=scopes or [],
        ttl=self._config.access_token_ttl,
    )
    return pyjwt.encode(
        payload,
        self._config.secret_key,
        algorithm=self._config.algorithm,
    )
  
  def create_refresh_token(
      self,
      user_id: str,
      roles: list[str] | None = None,
      scopes: list[str] | None = None,
  ) -> str:
    """Issue a signed JWT refresh token.

    Args:
        user_id: The user's UUID.
        roles:   Roles to embed in the payload.
        scopes:  Scopes to embed in the payload.

    Returns:
        A signed JWT string (type ``"refresh"``).
    """
    payload = self._build_payload(
        user_id=user_id,
        token_type="refresh",
        roles=roles or [],
        scopes=scopes or [],
        ttl=self._config.refresh_token_ttl,
    )
    return pyjwt.encode(
        payload,
        self._config.secret_key,
        algorithm=self._config.algorithm,
    )
  
  def create_token_pair(
      self,
      user_id: str,
      roles: list[str] | None = None,
      scopes: list[str] | None = None,
  ) -> TokenPair:
    """Issue an access + refresh token pair for a user.

    Args:
        user_id: The user's UUID.
        roles:   Roles to embed in both tokens.
        scopes:  Scopes to embed in both tokens.

    Returns:
        A TokenPair containing both signed tokens.
    """
    return TokenPair(
        access_token=self.create_access_token(user_id, roles, scopes),
        refresh_token=self.create_refresh_token(user_id, roles, scopes),
    )
  
  def decode_token(self, token: str, expected_type: str = "access") -> TokenPayload:
    """Decode and validate a JWT token's signature and claims.

    Does NOT check the blacklist — use ``verify_token()`` for full
    validation including revocation checks.

    Args:
        token:         The raw JWT string.
        expected_type: ``"access"`` or ``"refresh"`` — enforced against
                        the ``type`` claim in the payload.

    Returns:
        A TokenPayload with all decoded claims.

    Raises:
        TokenExpired: If the ``exp`` claim is in the past.
        InvalidToken: If the signature is invalid, claims are malformed,
                      or the token type does not match ``expected_type``.
    """
    try:
        raw = pyjwt.decode(
            token,
            self._config.secret_key,
            algorithms=[self._config.algorithm],
        )
    except ExpiredSignatureError:
        raise TokenExpired()
    except InvalidTokenError:
        raise InvalidToken()

    if raw.get("type") != expected_type:
        raise InvalidToken(
            f"Expected token type '{expected_type}', got '{raw.get('type')}'"
        )

    try:
        return TokenPayload(**raw)
    except Exception:
        raise InvalidToken("Token payload is missing required claims")
    
  async def blacklist_jti(self, jti: str, ttl_seconds: int) -> None:
      """Directly add a jti to the blacklist.

      Args:
          jti:         The JWT ID to blacklist.
          ttl_seconds: Seconds until the blacklist entry expires.
      """
      await self._blacklist.add(jti, ttl_seconds)

  async def is_blacklisted(self, jti: str) -> bool:
      """Check whether a jti is currently blacklisted.

      Args:
          jti: The JWT ID to check.

      Returns:
          True if blacklisted, False otherwise.
      """
      return await self._blacklist.contains(jti)
  
  async def blacklist_token(
    self, token: str, expected_type: str = "access"
  ) -> None:
      """Decode a token and blacklist its jti for the remaining lifetime.

      Used on logout to revoke the presented token.

      Args:
          token:         Raw JWT string to revoke.
          expected_type: Expected type claim value.

      Raises:
          TokenExpired: If the token is already expired (nothing to revoke).
          InvalidToken: If the token is malformed.
      """
      payload = self.decode_token(token, expected_type=expected_type)
      remaining = max(0, payload.exp - to_timestamp(utcnow()))
      await self.blacklist_jti(payload.jti, remaining)

  async def verify_token(
      self, token: str, expected_type: str = "access"
  ) -> TokenPayload:
      """Decode a token and verify it has not been revoked.

      This is the primary method auth middleware and dependencies should call.

      Args:
          token:         Raw JWT string.
          expected_type: Expected token type — ``"access"`` or ``"refresh"``.

      Returns:
          A validated TokenPayload.

      Raises:
          TokenExpired: Token has expired.
          InvalidToken: Token is malformed or wrong type.
          TokenRevoked: Token's jti is in the blacklist.
      """
      payload = self.decode_token(token, expected_type=expected_type)
      if await self.is_blacklisted(payload.jti):
          raise TokenRevoked()
      return payload
 