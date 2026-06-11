"""Registration flow for authwarden."""
from __future__ import annotations

from datetime import timedelta
from itsdangerous import URLSafeTimedSerializer

from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import EmailAlreadyExists
from authwarden.models.user import UserCreate, UserInDB, UserRead
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import generate_otp, hash_token, utcnow


async def register_flow(
    data: UserCreate,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
    notification_service: AbstractNotificationService,
) -> UserRead:
    """Register a new user account.
 
    Supports link-based and OTP-based verification, controlled by
    ``config.verification_method``.
 
    Args:
        data:                 Registration input.
        store:                User store implementation.
        config:               Application config.
        password_handler:     Password hashing and policy handler.
        notification_service: Notification delivery service.
 
    Returns:
        Public UserRead for the newly created user.
 
    Raises:
        WeakPassword:       Password violates the configured policy.
        EmailAlreadyExists: The email is already registered.
    """
    password_handler.check_policy(data.password)

    existing = await store.get_by_email(str(data.email))
    if existing is not None:
        raise EmailAlreadyExists()
    
    need_verification = config.require_email_verification
    now = utcnow()
    user = UserInDB(
        email=data.email,
        username=data.username,
        full_name=data.full_name,
        hashed_password=password_handler.hash_password(data.password),
        is_active=not need_verification,
        is_verified=not need_verification,
        created_at=now,
        updated_at=now,
    )

    if need_verification and config.verification_method == "otp":
        otp = generate_otp(config.otp_length)
        user.verification_otp_hash = hash_token(otp)
        user.verification_otp_expires_at = now + timedelta(seconds=config.otp_ttl)
    
    user = await store.create(user)

    if need_verification:
        if config.verification_method == "otp":
            await notification_service.send_verification_otp(user, otp) # type: ignore[possibly-undefined]
        else:
            serializer = URLSafeTimedSerializer(config.secret_key, salt="email-verification")
            token = serializer.dumps(user.email)
            link = f"{config.frontend_base_url}{config.verify_email_path}?token={token}"
            await notification_service.send_verification_link(user, link)

    return user.to_read()