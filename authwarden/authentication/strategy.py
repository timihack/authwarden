from __future__ import annotations

from typing import Protocol, runtime_checkable

from authwarden.models.token import TokenPair, TokenPayload


@runtime_checkable
class TokenStrategy(Protocol):
  async def issue_token_pair(
      self,
      user_id: str,
      roles: list[str] | None = None,
      scopes: list[str] | None = None,
  ) -> TokenPair: ...

  async def verify_token(self, token: str, expected_type: str = "access") -> TokenPayload: ...

  async def blacklist_token(self, token: str, expected_type: str = "access") -> None: ...