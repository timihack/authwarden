"""FastAPI dependency factories for resolving the authenticated user.
 
Two layers are exposed:
 
- get_token_payload(): decodes and verifies the JWT only — no DB call.
  Used internally by require_roles/require_scopes since role/scope checks
  work directly off the claims embedded at token-issue time. This is the
  standard JWT tradeoff: role changes take effect on next token refresh,
  not mid-token-lifetime. With short-lived access tokens (15 min default)
  this window is small and expected.
 
- get_current_user(): the full dependency — decodes the token AND fetches
  the user from the store, checking is_active on every request. This closes
  the one gap that actually matters in practice: a deactivated user's
  still-valid token should stop working immediately, not at expiry.
"""
from __future__ import annotations

from typing import Callable

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authwarden.authentication.jwt import JWTHandler
from authwarden.exceptions import AccountInactive, AuthError, UserNotFound
from authwarden.models.token import TokenPayload
from authwarden.models.user import UserInDB
from authwarden.storage.base import AbstractUserStore

_bearer_scheme = HTTPBearer(auto_error=True)

def build_get_token_payload(jwt_handler: JWTHandler) -> Callable:
  """Build a dependency that decodes and verifies the access token.

  Args:
      jwt_handler: The AuthWarden instance's JWTHandler.

  Returns:
      An async dependency callable returning TokenPayload.
  """
  async def get_token_payload(
      credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme),
  ) -> TokenPayload:
    try:
      return await jwt_handler.verify_token(
        credentials.credentials, expected_type="access"
      )
    except AuthError as e:
      raise HTTPException(status_code=e.status_code, detail=e.detail)
    
  return get_token_payload


def build_get_current_user(
    jwt_handler: JWTHandler, store: AbstractUserStore
) -> Callable:
  """Build a dependency that resolves the full authenticated user.

  Decodes the token, fetches the user from the store, and verifies
  the account is still active. Use this in route handlers that need
  the actual user object.

  Args:
      jwt_handler: The AuthWarden instance's JWTHandler.
      store:       The configured user store.

  Returns:
      An async dependency callable returning UserInDB.
  """
  get_token_payload = build_get_token_payload(jwt_handler)

  async def get_current_user(
      payload: TokenPayload = Depends(get_token_payload)
  ) -> UserInDB:
    user = await store.get_by_id(payload.sub)
    if user is None:
      raise HTTPException(
        status_code=UserNotFound.status_code, detail=UserNotFound.detail
      )
    if not user.is_active:
      raise HTTPException(
        status_code=AccountInactive.status_code, detail=AccountInactive.detail
      )
    return user
  return get_current_user
