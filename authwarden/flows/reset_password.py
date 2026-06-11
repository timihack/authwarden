"""Link-based password reset flow."""
from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import InvalidToken, SamePassword, TokenAlreadyUsed, TokenExpired
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow, verify_token_hash


async def reset_password_flow(
    token: str,
    new_password: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
    notification_service: AbstractNotificationService,
) -> None:
    """Reset password using a signed link token.

    Use ``reset_password_otp_flow`` when ``config.password_reset_method == "otp"``.

    Raises:
        TokenExpired, InvalidToken, TokenAlreadyUsed, WeakPassword, SamePassword.
    """
    s = URLSafeTimedSerializer(config.secret_key, salt="password-reset")
    try:
        email: str = s.loads(token, max_age=config.password_reset_ttl)
    except SignatureExpired:
        raise TokenExpired()
    except BadSignature:
        raise InvalidToken()

    user = await store.get_by_email(email)
    if user is None or not user.reset_token_hash:
        raise InvalidToken()
    if not verify_token_hash(token, user.reset_token_hash):
        raise InvalidToken()
    if user.reset_token_used_at is not None:
        raise TokenAlreadyUsed()

    password_handler.check_policy(new_password)

    if user.hashed_password and password_handler.verify_password(new_password, user.hashed_password):
        raise SamePassword()

    user.hashed_password = password_handler.hash_password(new_password)
    user.reset_token_used_at = utcnow()
    user.updated_at = utcnow()
    await store.update(user)
    await notification_service.send_password_changed(user)