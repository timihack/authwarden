"""Set a password for an OAuth-only account."""
from __future__ import annotations

from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import PasswordAlreadySet, UserNotFound
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow


async def set_password_flow(
    user_id: str,
    new_password: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
    notification_service: AbstractNotificationService,
) -> None:
    """Add a password login method to an OAuth-only account.

    Only valid when the account currently has no password set.

    Raises:
        UserNotFound, PasswordAlreadySet, WeakPassword.
    """
    user = await store.get_by_id(user_id)
    if user is None:
        raise UserNotFound()
    if user.hashed_password:
        raise PasswordAlreadySet()

    password_handler.check_policy(new_password)
    user.hashed_password = password_handler.hash_password(new_password)
    user.updated_at = utcnow()
    await store.update(user)
    await notification_service.send_password_changed(user)