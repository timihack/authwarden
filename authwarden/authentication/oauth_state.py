"""PKCE state storage for OAuth authorization flows.
 
State is single-use: get_and_delete() removes it on read, preventing replay.
TTL defaults to 10 minutes per the OAuth security spec.
"""
from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Literal, Protocol, runtime_checkable
from pydantic import BaseModel, Field

def _now() -> datetime:
  return datetime.now(timezone.utc)

class OAuthStateData(BaseModel):
  """Data persisted between the authorize and callback steps.

  Attributes:
      state:         Random CSRF-protection token (also the storage key).
      code_verifier: PKCE verifier generated at authorize time.
      provider:      Provider this state belongs to.
      created_at:    When the state was created.
      purpose:       "login" for the public auth flow, "connect" when
                      linking a provider to an already-authenticated user.
      user_id:       Set only when purpose="connect" — the authenticated
                      user initiating the link.
  """
  state: str
  code_verifier: str
  provider: str
  created_at: datetime = Field(default_factory=_now)
  purpose: Literal["login", "connect"] = "login"
  user_id: str | None = None


@runtime_checkable
class AbstractOAuthStateStore(Protocol):
  """Protocol for OAuth state storage backends."""
   
  async def create(self, data: OAuthStateData, ttl_seconds: int = 600) -> None:
    """
    Store state data with a TTL (default 10 minutes).
 
    Args:
        data:        The OAuthStateData to store.
        ttl_seconds: Seconds until this state expires.
    """
    ...
 
  async def get_and_delete(self, state: str) -> OAuthStateData | None:
    """Retrieve and immediately delete state data — single-use.

    Args:
        state: The state value to look up.

    Returns:
        OAuthStateData if found and not expired, None otherwise
        (covers both "never existed" and "expired" cases, which the
        caller should treat identically as OAuthStateMismatch).
    """
    ...
 
 
class MemoryOAuthStateStore:
  """In-memory PKCE state store. Suitable for single-process deployments
  or as a model for a Redis-backed implementation in production.
  """

  def __init__(self) -> None:
      self._store: dict[str, tuple[OAuthStateData, float]] = {}

  async def create(self, data: OAuthStateData, ttl_seconds: int = 600) -> None:
    """Store state with expiry timestamp."""
    self._store[data.state] = (data, time.time() + ttl_seconds)

  async def get_and_delete(self, state: str) -> OAuthStateData | None:
    """Pop and return state data if present and not expired."""
    entry = self._store.pop(state, None)
    if entry is None:
        return None
    data, expiry = entry
    if time.time() > expiry:
        return None
    return data

  def clear(self) -> None:
    """Reset store — useful between test cases."""
    self._store.clear()

  @property
  def size(self) -> int:
    return len(self._store)

