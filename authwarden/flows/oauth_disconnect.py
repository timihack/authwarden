"""Disconnect a linked OAuth provider from a user's account."""
from __future__ import annotations
from authwarden.exceptions import LastLoginMethod, OAuthAccountNotFound, UserNotFound
from authwarden.storage.base import AbstractUserStore


async def oauth_disconnect_flow(
    provider_name: str,
    *,
    current_user_id: str,
    store: AbstractUserStore,
) -> None:
    """Remove a linked OAuth provider, enforcing at least one login method remains.

    Raises:
        UserNotFound:        current_user_id does not exist.
        OAuthAccountNotFound: No linked account for this provider.
        LastLoginMethod:      This is the user's only login method (no password,
                              no other linked providers).
    """
    user = await store.get_by_id(current_user_id)
    if user is None:
        raise UserNotFound()

    accounts = await store.get_oauth_accounts_for_user(current_user_id)
    target = next((a for a in accounts if a.provider == provider_name), None)
    if target is None:
        raise OAuthAccountNotFound()

    has_password = bool(user.hashed_password)
    other_providers = [a for a in accounts if a.provider != provider_name]
    if not has_password and not other_providers:
        raise LastLoginMethod()

    await store.delete_oauth_account(current_user_id, provider_name)