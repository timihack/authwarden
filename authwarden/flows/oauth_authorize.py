"""OAuth authorization initiation flow."""
from __future__ import annotations

from authwarden.authentication.oauth import OAuthProviderBase, generate_pkce_pair
from authwarden.authentication.oauth_state import AbstractOAuthStateStore, OAuthStateData
from authwarden.core.config import WardenConfig
from authwarden.exceptions import OAuthProviderNotConfigured
from authwarden.utils import generate_secure_token


async def oauth_authorize_flow(
    provider_name: str,
    *,
    config: WardenConfig,
    providers: dict[str, OAuthProviderBase],
    state_store: AbstractOAuthStateStore,
    purpose: str = "login",
    user_id: str | None = None,
) -> str:
    """Generate the authorization URL and persist PKCE state.

    Args:
        provider_name: Provider key e.g. "google".
        config:        Application config.
        providers:     Dict of instantiated providers, keyed by name.
        state_store:   PKCE state storage.
        purpose:       "login" for public auth, "connect" when linking
                       to an already-authenticated user.
        user_id:       Required when purpose="connect".

    Returns:
        The authorization URL to redirect the user to.

    Raises:
        OAuthProviderNotConfigured: Provider not configured, disabled, or unknown.
    """
    provider_config = config.oauth_providers.get(provider_name)
    if not provider_config or not provider_config.enabled:
        raise OAuthProviderNotConfigured()

    provider = providers.get(provider_name)
    if provider is None:
        raise OAuthProviderNotConfigured()

    state = generate_secure_token()
    code_verifier, code_challenge = generate_pkce_pair()

    await state_store.create(OAuthStateData(
        state=state, code_verifier=code_verifier, provider=provider_name,
        purpose=purpose, user_id=user_id,
    ))

    return provider.build_authorization_url(state, code_challenge)