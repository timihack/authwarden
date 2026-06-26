"""FastAPI dependency factories for role and scope enforcement.
 
These operate on the decoded JWT payload (not a fresh DB fetch) since
roles/scopes are embedded at token-issue time — the standard, expected
JWT tradeoff. Use alongside get_current_user when a route needs both
the user object and a permission check.
 
Usage::
 
    @router.delete("/admin/users/{user_id}")
    async def delete_user(
        _payload=Depends(warden.require_roles("admin")),
    ):
        ...
"""
from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException

from authwarden.authentication.jwt import JWTHandler
from authwarden.dependencies.current_user import build_get_token_payload
from authwarden.exceptions import ForbiddenError
from authwarden.models.token import TokenPayload
from authwarden.permissions.policies import require_scopes as _require_scopes
from authwarden.permissions.roles import require_roles as _require_roles
 

def build_require_roles(jwt_handler: JWTHandler) -> Callable[..., Callable]:
  """Build a require_roles dependency FACTORY.

  Args:
      jwt_handler: The AuthWarden instance's JWTHandler.

  Returns:
      A function ``require_roles(*roles, require_all=False)`` that
      returns a Depends()-compatible callable enforcing the role check.
  """
  get_token_payload = build_get_token_payload(jwt_handler)

  def require_roles(*roles: str, require_all: bool = False) -> Callable:
    async def dependency(
        payload: TokenPayload = Depends(get_token_payload),
    ) -> TokenPayload:
      try:
        _require_roles(payload, *roles, require_all=require_all)
      except ForbiddenError as e:
        raise HTTPException(status_code=e.status_code, detail=e.detail)
      return payload
    
    return dependency
  
  return require_roles


def build_require_scopes(jwt_handler: JWTHandler) -> Callable[..., Callable]:
  """Build a require_scopes dependency FACTORY.

  Args:
      jwt_handler: The AuthWarden instance's JWTHandler.

  Returns:
      A function ``require_scopes(*scopes, require_all=False)`` that
      returns a Depends()-compatible callable enforcing the scope check.
  """
  get_token_payload = build_get_token_payload(jwt_handler)

  def require_scopes(*scopes: str, require_all: bool = False) -> Callable:
    async def dependency(
        payload: TokenPayload = Depends(get_token_payload),
    ) -> TokenPayload:
      try:
          _require_scopes(payload, *scopes, require_all=require_all)
      except ForbiddenError as e:
          raise HTTPException(status_code=e.status_code, detail=e.detail)
      return payload

    return dependency

  return require_scopes
