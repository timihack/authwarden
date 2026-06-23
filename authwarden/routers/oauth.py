"""OAuth router for authwarden.
 
The /authorize endpoint serves both the public login flow and the
authenticated connect flow from a single route: if a valid Bearer token
is present, it builds state with purpose="connect" (linking to that
user); otherwise purpose="login" (public auth). The callback/connect
endpoints below already validate purpose strictly, so this is safe.
"""
from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authwarden.authentication.jwt import JWTHandler
from authwarden.authentication.oauth import OAuthProviderBase
from authwarden.authentication.oauth_state import AbstractOAuthStateStore
from authwarden.core.config import WardenConfig
from authwarden.exceptions import AuthError
from authwarden.flows.oauth_accounts import list_oauth_accounts_flow
from authwarden.flows.oauth_authorize import oauth_authorize_flow
from authwarden.flows.oauth_callback import oauth_callback_flow
from authwarden.flows.oauth_connect import oauth_connect_flow
from authwarden.flows.oauth_disconnect import oauth_disconnect_flow
from authwarden.models.requests import (
    OAuthAuthorizeResponse,
    OAuthCallbackRequest,
    OAuthCallbackResponse,
)
from authwarden.models.user import OAuthAccountRead, UserInDB
from authwarden.notifications.service import AbstractNotificationService
from authwarden.routers._errors import handle_auth_errors
from authwarden.storage.base import AbstractUserStore
 
_optional_bearer = HTTPBearer(auto_error=False)

def build_oauth_router(
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    jwt_handler: JWTHandler,
    notification_service: AbstractNotificationService,
    providers: dict[str, OAuthProviderBase],
    state_store: AbstractOAuthStateStore,
    get_current_user: Callable,
) -> APIRouter:
  """Build the OAuth APIRouter for one AuthWarden instance.

  Returns:
      APIRouter with authorize/callback/connect/disconnect/accounts mounted.
  """
  router = APIRouter(prefix="/oauth")

  @router.get("/accounts", response_model=list[OAuthAccountRead])
  @handle_auth_errors
  async def list_accounts(user: UserInDB = Depends(get_current_user)) -> list[OAuthAccountRead]:
    """List all OAuth providers linked to the authenticated user."""
    return await list_oauth_accounts_flow(user.id, store=store)
  
  @router.get("/{provider}/authorize", response_model=OAuthAuthorizeResponse)
  @handle_auth_errors
  async def authorize(
    provider: str,
    credentials: HTTPAuthorizationCredentials | None = Depends(_optional_bearer)
  ) -> OAuthAuthorizeResponse:
      """Get the provider's authorization URL.

      If called with a valid Bearer token, builds state for the connect
      flow (linking to that user). Otherwise builds state for public login.
      """
      purpose = "login"
      user_id = None
      if credentials is not None:
         try:
            payload = await jwt_handler.verify_token(
               credentials.credentials, expected_type="access"
            )
            purpose = "connect"
            user_id = payload.sub
         except AuthError:
            pass # invalid/expired token on a public endpoint = - fall back to login
         
      url = await oauth_authorize_flow(
         provider, config=config, providers=providers, state_store=state_store,
         purpose=purpose, user_id=user_id
      )
      return OAuthAuthorizeResponse(authorization_url=url)

  @router.post("/{provider}/callback", response_model=OAuthCallbackResponse)
  @handle_auth_errors
  async def callback(provider: str, data: OAuthCallbackRequest) -> OAuthCallbackResponse:
    """Complete OAuth login — exchanges code, resolves account linking."""
    result = await oauth_callback_flow(
      provider, data.code, data.state, store=store, config=config,
      jwt_handler=jwt_handler, notification_service=notification_service,
      providers=providers, state_store=state_store, post_body=data.post_body,
    )
    return OAuthCallbackResponse(
      access_token=result.token_pair.access_token,
      refresh_token=result.token_pair.refresh_token,
      token_type=result.token_pair.token_type,
      user=result.user, is_new_user=result.is_new_user,
    )
  
  @router.post("/{provider}/connect", response_model=OAuthAccountRead)
  @handle_auth_errors
  async def connect(
     provider: str, data: OAuthCallbackRequest,
     user: UserInDB = Depends(get_current_user),
  ) -> OAuthAccountRead:
     """Link a new OAuth provider to the authenticated user's account."""
     return await oauth_connect_flow(
        provider, data.code, data.state, current_user_id=user.id,
        store=store, config=config, providers=providers,
        state_store=state_store, post_body=data.post_body
     )
  
  @router.delete("/{provider}/disconnect", status_code=204)
  @handle_auth_errors
  async def disconnect(
     provider: str, user: UserInDB = Depends(get_current_user),
  ) -> Response:
     """Unlink an OAuth provider - fails it's the only login method."""
     await oauth_disconnect_flow(provider, current_user_id=user.id, store=store)
     return Response(status_code=204)
  
  return router
 