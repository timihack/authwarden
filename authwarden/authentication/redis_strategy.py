from __future__ import annotations

import secrets
from typing import Any

from authwarden.core.config import WardenConfig
from authwarden.exceptions import InvalidToken, TokenExpired, TokenRevoked
from authwarden.models.token import TokenPair, TokenPayload
from authwarden.utils import generate_jti, hash_token, to_timestamp, utcnow


class RedisTokenStrategy:
  _TOKEN_PREFIX = "authwarden:token:"
  _REVOKED_PREFIX = "authwarden:revoked:"

  def __init__(self, config: WardenConfig, redis_client: Any) -> None:
    self._config = config
    self._redis = redis_client

  @classmethod
  def from_url(cls, config: WardenConfig, redis_url: str) -> RedisTokenStrategy:
    import redis.asyncio as redis

    return cls(config, redis.from_url(redis_url))

  async def issue_token_pair(
      self,
      user_id: str,
      roles: list[str] | None = None,
      scopes: list[str] | None = None,
  ) -> TokenPair:
    return TokenPair(
      access_token=await self._issue(
          user_id,
          "access",
          self._config.access_token_ttl,
          roles,
          scopes,
      ),
      refresh_token=await self._issue(
          user_id,
          "refresh",
          self._config.refresh_token_ttl,
          roles,
          scopes,
      ),
    )

  async def verify_token(self, token: str, expected_type: str = "access") -> TokenPayload:
    digest = hash_token(token)
    raw = await self._redis.get(self._TOKEN_PREFIX + digest)
    if raw is None:
      if await self._redis.exists(self._REVOKED_PREFIX + digest):
        raise TokenRevoked()
      raise InvalidToken()
    return self._checked(TokenPayload.model_validate_json(raw), expected_type)

  async def blacklist_token(self, token: str, expected_type: str = "access") -> None:
    digest = hash_token(token)
    raw = await self._redis.get(self._TOKEN_PREFIX + digest)
    if raw is None:
      raise InvalidToken()
    payload = self._checked(TokenPayload.model_validate_json(raw), expected_type)
    remaining = max(1, payload.exp - to_timestamp(utcnow()))
    async with self._redis.pipeline(transaction=True) as pipe:
      pipe.setex(self._REVOKED_PREFIX + digest, remaining, "1")
      pipe.delete(self._TOKEN_PREFIX + digest)
      await pipe.execute()

  async def _issue(
      self,
      user_id: str,
      token_type: str,
      ttl: int,
      roles: list[str] | None,
      scopes: list[str] | None,
  ) -> str:
    token = secrets.token_urlsafe(32)
    now = to_timestamp(utcnow())
    payload = TokenPayload(
      sub = user_id,
      jti = generate_jti(),
      type=token_type,
      roles=roles or [],
      scopes=scopes or [],
      iat=now,
      exp=now + ttl,
    )
    await self._redis.setex(self._TOKEN_PREFIX + hash_token(token), ttl, payload.model_dump_json())
    return token

  @staticmethod
  def _checked(payload: TokenPayload, expected_type: str) -> TokenPayload:
    if payload.type != expected_type:
      raise InvalidToken(f"Expected token type '{expected_type}', got '{payload.type}'")
    if payload.exp < to_timestamp(utcnow()):
      raise TokenExpired("Token has expired")
    return payload