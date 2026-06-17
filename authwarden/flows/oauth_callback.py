"""OAuth callback flow — code exchange + account linking logic."""
from __future__ import annotations

from typing import Any
from pydantic import BaseModel

from authwarden.authentication.encryption import encrypt_token
from authwarden.authentication.jwt import JWTHandler
from authwarden.authentication.oauth import OAuthProviderBase, _token_expiry
from authwarden.authentication.oauth_state import AbstractOAuthStateStore
from authwarden.core.config import WardenConfig
from authwarden.exceptions import (
    EmailAlreadyRegistered, OAuthCodeExchangeFailed, OAuthProviderNotConfigured,
    OAuthStateMismatch, OAuthUserInfoFailed, UserNotFound,
)
from authwarden.models.token import TokenPair
from authwarden.models.user import OAuthAccount, UserInDB, UserRead
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow


class OAuthCallbackResult(BaseModel):
    """Result of a successful OAuth callback — login case."""
    token_pair: TokenPair
    user: UserRead
    is_new_user: bool


async def oauth_callback_flow(
    provider_name: str,
    code: str,
    state: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    jwt_handler: JWTHandler,
    notification_service: AbstractNotificationService,
    providers: dict[str, OAuthProviderBase],
    state_store: AbstractOAuthStateStore,
    post_body: dict[str, Any] | None = None,
) -> OAuthCallbackResult:
    """Complete an OAuth login — validates state, exchanges code, links account.

    Account linking resolution order:
      1. OAuthAccount exists for (provider, provider_user_id) → log in as that user
      2. No account, but email matches a local user → auto-link (if enabled) or raise
      3. No account, no email match (or no email) → auto-register new user

    Args:
        provider_name: Provider key.
        code:          Authorization code from the callback.
        state:         CSRF state value to validate against stored PKCE state.
        store:         User store.
        config:        Application config.
        jwt_handler:   JWT handler for issuing tokens.
        notification_service: For welcome emails on new registration.
        providers:     Dict of instantiated providers.
        state_store:   PKCE state storage.
        post_body:     Raw callback POST body — required for Apple's first-login
                       name extraction; ignored by other providers.

    Returns:
        OAuthCallbackResult with token pair, user, and is_new_user flag.

    Raises:
        OAuthStateMismatch:        State invalid, expired, or wrong purpose.
        OAuthProviderNotConfigured: Provider not configured or unknown.
        OAuthCodeExchangeFailed:   Token exchange with provider failed.
        OAuthUserInfoFailed:       Fetching user info from provider failed.
        EmailAlreadyRegistered:    Email matches existing user, auto_link_by_email=False.
    """
    state_data = await state_store.get_and_delete(state)
    if state_data is None or state_data.provider != provider_name or state_data.purpose != "login":
        raise OAuthStateMismatch()

    provider_config = config.oauth_providers.get(provider_name)
    if not provider_config or not provider_config.enabled:
        raise OAuthProviderNotConfigured()
    provider = providers.get(provider_name)
    if provider is None:
        raise OAuthProviderNotConfigured()

    try:
        token = await provider.exchange_code(code, state_data.code_verifier)
    except Exception as e:
        raise OAuthCodeExchangeFailed() from e

    try:
        if provider_name == "apple":
            userinfo = await provider.fetch_userinfo(token, post_body=post_body)
        else:
            userinfo = await provider.fetch_userinfo(token)
    except Exception as e:
        raise OAuthUserInfoFailed() from e

    access_token_enc = encrypt_token(token["access_token"], config.secret_key) if token.get("access_token") else None
    refresh_token_enc = encrypt_token(token["refresh_token"], config.secret_key) if token.get("refresh_token") else None
    expires_at = _token_expiry(token)

    is_new_user = False
    existing_account = await store.get_oauth_account(provider_name, userinfo.provider_user_id)

    if existing_account is not None:
        # Case 1 — existing link
        user = await store.get_by_id(existing_account.user_id)
        if user is None:
            raise UserNotFound()
    else:
        user = None
        if userinfo.email:
            user = await store.get_by_email(userinfo.email)

        if user is not None:
            # Case 2 — email matches existing local user
            if not config.auto_link_by_email:
                raise EmailAlreadyRegistered()
        else:
            # Case 3/4 — auto-register new user
            now = utcnow()
            email = userinfo.email or f"{provider_name}_{userinfo.provider_user_id}@oauth.authwarden.placeholder"
            user = UserInDB(
                email=email,
                full_name=userinfo.full_name,
                hashed_password=None,
                is_active=True,
                is_verified=True,
                created_at=now, updated_at=now,
            )
            user = await store.create(user)
            is_new_user = True
            if userinfo.email:
                await notification_service.send_welcome(user)

        account = OAuthAccount(
            user_id=user.id,
            provider=provider_name,
            provider_user_id=userinfo.provider_user_id,
            email=userinfo.email,
            access_token=access_token_enc,
            refresh_token=refresh_token_enc,
            token_expires_at=expires_at,
        )
        await store.create_oauth_account(account)

    pair = jwt_handler.create_token_pair(user.id, roles=user.roles, scopes=user.scopes)
    return OAuthCallbackResult(token_pair=pair, user=user.to_read(), is_new_user=is_new_user)