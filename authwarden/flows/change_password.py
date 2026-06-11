"""Change password flow (authenticated)."""
from __future__ import annotations

from authwarden.authentication.jwt import JWTHandler
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import InvalidCredentials, PasswordNotSet, SamePassword, UserNotFound
from authwarden.models.token import TokenPair
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow


async def change_password_flow(
    user_id: str,
    current_password: str,
    new_password: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
    jwt_handler: JWTHandler,
    notification_service: AbstractNotificationService,
) -> TokenPair:
    """Change the authenticated user's password.

    Returns a fresh TokenPair so the current session stays valid.

    Raises:
        UserNotFound, PasswordNotSet, InvalidCredentials, WeakPassword, SamePassword.
    """
    user = await store.get_by_id(user_id)
    if user is None:
        raise UserNotFound()
    if not user.hashed_password:
        raise PasswordNotSet()
    if not password_handler.verify_password(current_password, user.hashed_password):
        raise InvalidCredentials()

    password_handler.check_policy(new_password)

    if password_handler.verify_password(new_password, user.hashed_password):
        raise SamePassword()

    user.hashed_password = password_handler.hash_password(new_password)
    user.updated_at = utcnow()
    await store.update(user)
    await notification_service.send_password_changed(user)
    return jwt_handler.create_token_pair(user.id, roles=user.roles, scopes=user.scopes)