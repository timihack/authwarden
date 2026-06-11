"""Forgot password flow — supports link and OTP modes."""
from __future__ import annotations

from datetime import timedelta

from itsdangerous import URLSafeTimedSerializer
from authwarden.core.config import WardenConfig
from authwarden.exceptions import RateLimited
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import generate_otp, hash_token, utcnow

_RATE_LIMIT_SECONDS = 60


async def forgot_password_flow(
    identifier: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    notification_service: AbstractNotificationService,
) -> None:
    """Initiate a password reset via link or OTP.

    Anti-enumeration: unknown identifier and inactive accounts return silently.
    Only RateLimited is exposed.

    Args:
        identifier: Email address or phone number.
    """
    user = await store.get_by_email(identifier)
    if user is None:
        user = await store.get_by_phone(identifier)
    if user is None or not user.is_active:
        return

    if user.last_reset_request_at is not None:
        elapsed = (utcnow() - user.last_reset_request_at).total_seconds()
        if elapsed < _RATE_LIMIT_SECONDS:
            raise RateLimited(
                f"Wait {int(_RATE_LIMIT_SECONDS - elapsed)}s before requesting another reset."
            )

    user.last_reset_request_at = utcnow()
    user.updated_at = utcnow()

    if config.password_reset_method == "otp":
        otp = generate_otp(config.otp_length)
        user.reset_otp_hash = hash_token(otp)
        user.reset_otp_expires_at = utcnow() + timedelta(seconds=config.otp_ttl)
        await store.update(user)
        await notification_service.send_password_reset_otp(user, otp)
    else:
        # Link mode — requires email in token payload
        if not user.email:
            return  # phone-only users must use OTP mode
        s = URLSafeTimedSerializer(config.secret_key, salt="password-reset")
        token = s.dumps(user.email)
        user.reset_token_hash = hash_token(token)
        user.reset_token_used_at = None
        await store.update(user)
        link = f"{config.frontend_base_url}{config.reset_password_path}?token={token}"
        await notification_service.send_password_reset_link(user, link)