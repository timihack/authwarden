"""List linked OAuth accounts for a user."""
from __future__ import annotations

from authwarden.models.user import OAuthAccountRead
from authwarden.storage.base import AbstractUserStore


async def list_oauth_accounts_flow(
    user_id: str, *, store: AbstractUserStore,
) -> list[OAuthAccountRead]:
    """Return all linked OAuth accounts for a user, excluding tokens.

    Args:
        user_id: The user's UUID.
        store:   User store.

    Returns:
        List of OAuthAccountRead — public-safe, no access/refresh tokens.
    """
    accounts = await store.get_oauth_accounts_for_user(user_id)
    return [
        OAuthAccountRead(id=a.id, provider=a.provider, email=a.email, created_at=a.created_at)
        for a in accounts
    ]