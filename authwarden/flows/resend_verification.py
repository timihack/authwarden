"""Rsend verification flow - supports both link and OTP modes"""
from __future__ import annotations

from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer

from authwarden.core.config import WardenConfig
from authwarden.exceptions import RateLimited
from authwarden.models import user
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import generate_otp, hash_token, utcnow


async def resend_verification_flow(
    identifier: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    notification_service: AbstractNotificationService,
) -> None:
    """Resend the verification link or OTP to an unverified user.
 
    Anti-enumeration: unknown identifier and already-verified both
    return silently. Only RateLimited is exposed.
 
    Args:
        identifier: Email address or phone number.
    """
    user = await store.get_by_email(identifier)
    if user is None:
        user = await store.get_by_phone(identifier)
    if user is None or user.is_verified:
        return
    
    if user.last_verification_sent_at is not None:
        elapsed = (utcnow() - user.last_verification_sent_at).total_seconds()
        if elapsed < config.resend_verification_cooldown:
            raise RateLimited(
                f"Wait {int(config.resend_verification_cooldown - elapsed)}s before resending"
            )
        
    if config.verification_method == "otp":
        otp = generate_otp(config.otp_length)
        user.verification_otp_hash = hash_token(otp)
        user.verification_otp_expires_at = utcnow() + timedelta(seconds=config.otp_ttl)
        user.last_verification_sent_at = utcnow()
        await store.update(user)
        await notification_service.send_verification_otp(user, otp)
    else:
        s = URLSafeTimedSerializer(config.secret_key, salt="email-verification")
        token = s.dumps(user.email)
        link = f"{config.frontend_base_url}{config.verify_email_path}?token={token}"
        user.last_verification_sent_at = utcnow()
        user.updated_at = utcnow()
        await store.update(user)
        await notification_service.send_verification_link(user, link)
    