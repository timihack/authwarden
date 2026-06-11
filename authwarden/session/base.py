"""Session backend protocol and data model for authwarden.

Sessions are optional — only active when ``session_backend`` is configured.
They store per-device login metadata and enable device-level logout.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Protocol, runtime_checkable

from pydantic import BaseModel, Field


def _now() -> datetime: return datetime.now(timezone.utc)
def _uuid() -> str: return str(uuid.uuid4())


class SessionData(BaseModel):
  """Metadata for a single authenticated session (one device / browser tab).

  Attributes:
      session_id: UUID identifying this session.
      user_id:    UUID of the owning user.
      user_agent: HTTP User-Agent string from the login request.
      ip_hash:    SHA-256 hash of the client IP — stored for fingerprinting,
                  never the raw IP.
      issued_at:  When the session was created.
      expires_at: When the session expires (matches refresh token TTL).
  """

  session_id: str = Field(default_factory=_uuid)
  user_id: str
  user_agent: str | None = None
  ip_hash: str | None = None
  issued_at: datetime = Field(default_factory=_now)
  expires_at: datetime

  model_config = {"from_attributes": True}


@runtime_checkable
class AbstractSessionBackend(Protocol):
  """Protocol all session backends must satisfy.

  Sessions are keyed by ``session_id``. Implementations are responsible
  for respecting ``expires_at`` — expired sessions should not be returned
  by ``get()``.
  """

  async def create(self, session: SessionData) -> SessionData:
      """Persist a new session.

      Args:
          session: Fully populated SessionData instance.

      Returns:
          The created SessionData.
      """
      ...

  async def get(self, session_id: str) -> SessionData | None:
      """Retrieve a session by ID.

      Args:
          session_id: The session UUID to look up.

      Returns:
          SessionData if found and not expired, None otherwise.
      """
      ...

  async def delete(self, session_id: str) -> None:
      """Delete a single session (e.g. on logout from one device).

      Args:
          session_id: The session UUID to delete.
      """
      ...

  async def delete_all_for_user(self, user_id: str) -> None:
      """Delete all sessions for a user (e.g. on password reset).

      Args:
          user_id: The user UUID whose sessions should all be removed.
      """
      ...

  async def get_all_for_user(self, user_id: str) -> list[SessionData]:
      """Return all active (non-expired) sessions for a user.

      Args:
          user_id: The user UUID to query.

      Returns:
          List of active SessionData records, may be empty.
      """
      ...