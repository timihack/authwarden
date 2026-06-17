"""Connect an OAuth provider to an already-authenticated user."""
from __future__ import annotations

from typing import Any

from authwarden.authentication.encryption import encrypt_token
from authwarden.authentication.oauth import OAuthProviderBase, _token_expiry
from authwarden.authentication.oauth_state import AbstractOAuthStateStore
from authwarden.core.config import WardenConfig
from authwarden.exceptions import (
    OAuthCodeExchangeFailed, OAuthProviderNotConfigured, OAuthStateMismatch,
    OAuthUserInfoFailed, ProviderAlreadyLinked,
)
from authwarden.models.user import OAuthAccount, OAuthAccountRead
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow


async def oauth_connect_flow(
    provider_name: str,
    code: str,
    state: str,
    *,
    current_user_id: str,
    store: AbstractUserStore,
    config: WardenConfig,
    providers: dict[str, OAuthProviderBase],
    state_store: AbstractOAuthStateStore,
    post_body: dict[str, Any] | None = None,
) -> OAuthAccountRead:
    """Link a new OAuth provider to an existing authenticated account.

    Raises:
        OAuthStateMismatch:        State invalid, expired, wrong purpose/user.
        OAuthProviderNotConfigured: Provider not configured.
        OAuthCodeExchangeFailed, OAuthUserInfoFailed.
        ProviderAlreadyLinked:     This provider is already linked.
    """
    state_data = await state_store.get_and_delete(state)
    if (state_data is None or state_data.provider != provider_name
            or state_data.purpose != "connect" or state_data.user_id != current_user_id):
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

    existing = await store.get_oauth_account(provider_name, userinfo.provider_user_id)
    if existing is not None:
        raise ProviderAlreadyLinked()

    access_token_enc = encrypt_token(token["access_token"], config.secret_key) if token.get("access_token") else None
    refresh_token_enc = encrypt_token(token["refresh_token"], config.secret_key) if token.get("refresh_token") else None

    account = OAuthAccount(
        user_id=current_user_id,
        provider=provider_name,
        provider_user_id=userinfo.provider_user_id,
        email=userinfo.email,
        access_token=access_token_enc,
        refresh_token=refresh_token_enc,
        token_expires_at=_token_expiry(token),
    )
    account = await store.create_oauth_account(account)

    return OAuthAccountRead(
        id=account.id, provider=account.provider,
        email=account.email, created_at=account.created_at,
    )