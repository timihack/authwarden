"""Request-scoped auth context for authwarden.
 
FastAPI's Depends() already provides request scoping for most needs.
This module exists for code deep in business logic (e.g. logging, audit
trails) that wants access to "who is making this request" without
threading a UserInDB parameter through every function call.
 
Usage::
 
    from authwarden.core.context import current_auth_context
 
    @router.post("/some-business-action")
    async def handler(user=Depends(warden.current_user)):
        current_auth_context.set(AuthContext(user_id=user.id, roles=user.roles))
        await do_something_that_logs_the_actor()
 
    async def do_something_that_logs_the_actor():
        ctx = current_auth_context.get()
        logger.info(f"action performed by {ctx.user_id if ctx else 'anonymous'}")
 
Not required for normal route handlers — only useful when avoiding
parameter threading through deep call chains.
"""
from __future__ import annotations

from contextvars import ContextVar
from pydantic import BaseModel


class AuthContext(BaseModel):
  """Minimal snapshot of the authenticated actor for the current request.

  Attributes:
      user_id: UUID of the authenticated user.
      roles:   Roles embedded in the request's JWT at issue time.
      scopes:  Scopes embedded in the request's JWT at issue time.
  """
  user_id: str
  roles: list[str] = []
  scopes: list[str] = []

current_auth_context: ContextVar[AuthContext | None] = ContextVar(
  "current_auth_context", default=None
)