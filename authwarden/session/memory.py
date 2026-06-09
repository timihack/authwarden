"""In-memory session backend for authwarden.
 
Suitable for testing and single-process development only.
Data is lost on process restart — use RedisSessionBackend for production.
"""
from __future__ import annotations

from authwarden.session.base import AbstractSessionBackend, SessionData
from authwarden.utils import utcnow



class MemorySessionBackend:
  """A plain dict-backed implementation of AbstractSessionBackend.

  Satisfies the protocol via structural subtyping — no inheritance needed.
  Expired sessions are lazily evicted on access.

  Usage::

      backend = MemorySessionBackend()
      session = SessionData(user_id="uid", expires_at=utcnow() + timedelta(days=7))
      await backend.create(session)
  """

  def __init__(self) -> None:
    self._sessions: dict[str, SessionData] = {} # session_id -> SessionData

  async def create(self, session: SessionData) -> SessionData:
    """Store a new session.

    Args:
        session: Fully populated SessionData instance.

    Returns:
        The stored SessionData instance.
    """
    self._sessions[session.session_id] = session
    return session
  
  async def get(self, session_id: str) -> SessionData | None:
      """Return the session if it exists and has not expired.

      Expired sessions are evicted on access.

      Args:
          session_id: The session UUID to look up.

      Returns:
          SessionData if found and valid, None otherwise.
      """
      session = self._sessions.get(session_id)
      if session is None:
          return None
      if utcnow() >= session.expires_at:
          del self._sessions[session_id]
          return None
      return session

  async def delete(self, session_id: str) -> None:
      """Remove a session by ID.

      Args:
          session_id: The session UUID to remove.
      """
      self._sessions.pop(session_id, None)

  async def delete_all_for_user(self, user_id: str) -> None:
      """Remove all sessions belonging to a user.

      Args:
          user_id: UUID of the user whose sessions should be cleared.
      """
      to_delete = [
          sid for sid, s in self._sessions.items() if s.user_id == user_id
      ]
      for sid in to_delete:
          del self._sessions[sid]

  async def get_all_for_user(self, user_id: str) -> list[SessionData]:
      """Return all active sessions for a user, evicting expired ones.

      Args:
          user_id: UUID of the user to query.

      Returns:
          List of non-expired SessionData records.
      """
      now = utcnow()
      active, expired = [], []
      for sid, session in self._sessions.items():
          if session.user_id != user_id:
              continue
          if now >= session.expires_at:
              expired.append(sid)
          else:
              active.append(session)
      for sid in expired:
          del self._sessions[sid]
      return active

  def clear(self) -> None:
      """Reset all sessions — useful between test cases."""
      self._sessions.clear()

  @property
  def session_count(self) -> int:
      """Return the total number of stored sessions (including expired)."""
      return len(self._sessions)
 
 
# Verify protocol satisfaction at import time
assert isinstance(MemorySessionBackend(), AbstractSessionBackend), (
    "MemorySessionBackend does not satisfy AbstractSessionBackend protocol"
)
 