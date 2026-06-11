"""Link-based email verification flow."""
from __future__ import annotations

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from authwarden.core.config import WardenConfig
from authwarden.exceptions import AlreadyVerified, InvalidToken, TokenExpired
from authwarden.models.user import UserRead
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow


async def verify_email_flow(
    token: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    notification_service: AbstractNotificationService,
) -> UserRead:
  """Verify email using a signed link token.
 
    Use ``verify_otp_flow`` when ``config.verification_method == "otp"``.
 
    Raises:
        TokenExpired:    Token TTL elapsed.
        InvalidToken:    Bad signature or user not found.
        AlreadyVerified: Email already verified.
  """
  s = URLSafeTimedSerializer(config.secret_key, salt="email-verification")
  try:
    email: str = s.loads(token, max_age=config.email_verification_ttl)
  except SignatureExpired:
    raise TokenExpired()
  except BadSignature:
    raise InvalidToken()
  
  user = await store.get_by_email(email)
  if user is None:
    raise InvalidToken()
  if user.is_verified:
    raise AlreadyVerified()

  user.is_verified = True
  user.is_active = True
  user.updated_at = utcnow()
  user = await store.update(user)

  await notification_service.send_welcome(user)
  return user.to_read()