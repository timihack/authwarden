"""OTP-based verification flow (email or phone)."""
from __future__ import annotations

from authwarden.core.config import WardenConfig
from authwarden.exceptions import AlreadyVerified, InvalidToken, TokenExpired
from authwarden.models.user import UserRead
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow, verify_token_hash


async def verify_otp_flow(
    identifier: str,
    otp: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    notification_service: AbstractNotificationService,
) -> UserRead:
    """Verify an account using a numeric OTP.
 
    The identifier can be an email address or phone number —
    the store is queried for both.
 
    Args:
        identifier:           Email address or phone number used at registration.
        otp:                  The OTP the user received via email or SMS.
        store:                User store implementation.
        config:               Application config.
        notification_service: Notification service (for welcome message).
 
    Returns:
        Updated UserRead with is_verified=True.
 
    Raises:
        TokenExpired:    OTP has expired.
        InvalidToken:    OTP is incorrect or user not found.
        AlreadyVerified: Account already verified.
    """
    # Resolve user - try email then phone
    user = await store.get_by_email(identifier)
    if user is None:
        user = await store.get_by_phone(identifier)
    if user is None:
        raise InvalidToken()
    
    if user.is_verified:
        raise AlreadyVerified()
    
    if (not user.verification_otp_expires_at) \
          or (utcnow() > user.verification_otp_expires_at):
        raise TokenExpired()

    # Attempt limit check
    if config.max_otp_attempts > 0 and user.verification_otp_attempts >= config.max_otp_attempts:
        # Invalidate OTP - force resend
        user.verification_otp_hash = None
        user.verification_otp_expires_at = None
        user.verification_otp_attempts = 0
        user.updated_at = utcnow()
        await store.update(user)
        raise TokenExpired("Too many attempts - please request a new OTP.")
    
    if not user.verification_otp_hash or not verify_token_hash(otp, user.verification_otp_hash):
        if config.max_otp_attempts > 0:
            user.verification_otp_attempts += 1
            # Invalidate immediately when limit is reached
            if user.verification_otp_attempts >= config.max_otp_attempts:
                user.verification_otp_hash = None
                user.verification_otp_expires_at = None
                user.verification_otp_attempts = 0
            user.updated_at = utcnow()
            await store.update(user)
        raise InvalidToken()  
    
    user.is_verified = True
    user.is_active = True
    user.verification_otp_hash = None
    user.verification_otp_expires_at = None
    user.verification_otp_attempts = 0
    user.updated_at = utcnow()
    user = await store.update(user)

    await notification_service.send_welcome(user)
    return user.to_read()