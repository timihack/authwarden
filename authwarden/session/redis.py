"""Redis-backed session backend for authwarden.

Requires the ``redis`` optional dependency::

  pip install authwarden[redis]

Sessions are stored as JSON strings with native Redis TTL expiry.
A user-level index (Redis Set) tracks all session IDs per user,
enabling efficient delete_all_for_user() without a full scan.
"""
from __future__ import annotations

from authwarden.session.base import SessionData
from authwarden.utils import utcnow


try:
  import redis.asyncio as aioredis
  _REDIS_AVAILABLE = True
except ImportError:
  _REDIS_AVAILABLE = False


class RedisSessionBackend:
  """Redis-backed session store.

  Args:
      redis_url: Redis connection URL, e.g. ``"redis://localhost:6379"``.
                  Passed directly to ``redis.asyncio.from_url()``.

  Raises:
      ImportError: If the ``redis`` package is not installed.
  """

  _SESSION_PREFIX = "authwarden:session:"
  _USER_INDEX_PREFIX = "authwarden:user_sessions:"

  def __init__(self, redis_url: str) -> None:
      if not _REDIS_AVAILABLE:
          raise ImportError(
              "Redis session backend requires the 'redis' package. "
              "Install it with: pip install authwarden[redis]"
          )
      self._client = aioredis.from_url(redis_url, decode_responses=True)

  def _session_key(self, session_id: str) -> str:
      return f"{self._SESSION_PREFIX}{session_id}"

  def _user_index_key(self, user_id: str) -> str:
      return f"{self._USER_INDEX_PREFIX}{user_id}"

  async def create(self, session: SessionData) -> SessionData:
      """Persist a session in Redis with TTL derived from ``expires_at``.

      Also adds the session_id to the user's index Set so it can be
      looked up by user_id efficiently.

      Args:
          session: Fully populated SessionData instance.

      Returns:
          The same SessionData instance.
      """
      ttl = int((session.expires_at - utcnow()).total_seconds())
      ttl = max(1, ttl)
      await self._client.setex(
          self._session_key(session.session_id),
          ttl,
          session.model_dump_json(),
      )
      await self._client.sadd(
          self._user_index_key(session.user_id),
          session.session_id,
      )
      return session

  async def get(self, session_id: str) -> SessionData | None:
      """Retrieve a session by ID.

      Redis handles expiry automatically — if the key is gone, the
      session has expired.

      Args:
          session_id: The session UUID to look up.

      Returns:
          SessionData if found, None if expired or not found.
      """
      data = await self._client.get(self._session_key(session_id))
      if data is None:
          return None
      return SessionData.model_validate_json(data)

  async def delete(self, session_id: str) -> None:
      """Delete a single session and remove it from the user index.

      Args:
          session_id: The session UUID to delete.
      """
      session = await self.get(session_id)
      if session:
          await self._client.srem(
              self._user_index_key(session.user_id),
              session_id,
          )
      await self._client.delete(self._session_key(session_id))

  async def delete_all_for_user(self, user_id: str) -> None:
      """Delete all sessions for a user and clear the index.

      Args:
          user_id: UUID of the user whose sessions should all be removed.
      """
      index_key = self._user_index_key(user_id)
      session_ids: set[str] = await self._client.smembers(index_key)
      if session_ids:
          session_keys = [self._session_key(sid) for sid in session_ids]
          await self._client.delete(*session_keys)
      await self._client.delete(index_key)

  async def get_all_for_user(self, user_id: str) -> list[SessionData]:
      """Return all active sessions for a user.

      Stale index entries (sessions whose Redis keys have expired) are
      cleaned up lazily during this call.

      Args:
          user_id: UUID of the user to query.

      Returns:
          List of active SessionData records.
      """
      index_key = self._user_index_key(user_id)
      session_ids: set[str] = await self._client.smembers(index_key)

      sessions: list[SessionData] = []
      stale_ids: list[str] = []

      for sid in session_ids:
          session = await self.get(sid)
          if session is None:
              stale_ids.append(sid)
          else:
              sessions.append(session)

      if stale_ids:
          await self._client.srem(index_key, *stale_ids)

      return sessions