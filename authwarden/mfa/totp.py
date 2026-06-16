"""TOTP MFA setup, confirm and disable flows."""
from __future__ import annotations

import pyotp
from pydantic import BaseModel

from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import (
  InvalidCredentials, InvalidMFACode, MFAAlreadyEnabled,
  MFANotEnabled,PasswordNotSet, UserNotFound,
)
from authwarden.notifications.service import AbstractNotificationService
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import generate_backup_codes, utcnow


class MFASetupResult(BaseModel):
  """Returned once from setup_mfa_flow. backup_codes shown in plaintext ONCE only."""
  secret: str
  qr_uri: str
  backup_codes: list[str]


async def setup_mfa_flow(
    user_id: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
) -> MFASetupResult:
  """Initiate MFA setup - generate TOTP secret and hashed backup codes.

  Secret stored as mfa_pending_secret until confirmed.
  Backup codes returned in plaintext once, stored as argon2 hasehes.

  Raises:
      UserNotFound, MFAAlreadyEnabled.
  """
  user = await store.get_by_id(user_id)
  if user is None:
    raise UserNotFound
  if user.mfa_enabled:
    raise MFAAlreadyEnabled()
  
  secret = pyotp.random_base32()
  qr_uri = pyotp.TOTP(secret).provisioning_uri(
    name=user.email, issuer_name=config.mfa_issuer_name,
  )
  plain_codes = generate_backup_codes(count=8, length=8)
  hashed_codes = [password_handler.hash_password(c) for c in plain_codes]

  user.mfa_pending_secret = secret
  user.backup_codes = hashed_codes
  user.updated_at = utcnow()
  await store.update(user)

  return MFASetupResult(secret=secret, qr_uri=qr_uri, backup_codes=plain_codes)


async def confirm_mfa_flow(
    user_id: str,
    totp_code: str,
    *,
    store: AbstractUserStore,
    notification_service: AbstractNotificationService,
) -> None:
    """Confirm MFA by verifying first TOTP code — promotes pending secret to active.
 
    Raises: UserNotFound, MFAAlreadyEnabled, InvalidMFACode.
    """
    user = await store.get_by_id(user_id)
    if user is None:
        raise UserNotFound()
    if user.mfa_enabled:
        raise MFAAlreadyEnabled()
    if not user.mfa_pending_secret:
        raise InvalidMFACode("MFA setup not initiated — call setup first")
    if not pyotp.TOTP(user.mfa_pending_secret).verify(totp_code, valid_window=1):
        raise InvalidMFACode()
 
    user.mfa_secret = user.mfa_pending_secret
    user.mfa_pending_secret = None
    user.mfa_enabled = True
    user.updated_at = utcnow()
    await store.update(user)
    await notification_service.send_mfa_enabled(user)
 
 
async def disable_mfa_flow(
    user_id: str,
    password: str,
    totp_or_backup_code: str,
    *,
    store: AbstractUserStore,
    password_handler: PasswordHandler,
    notification_service: AbstractNotificationService,
) -> None:
    """Disable MFA — requires password + TOTP or backup code.
 
    Raises: UserNotFound, MFANotEnabled, PasswordNotSet, InvalidCredentials, InvalidMFACode.
    """
    user = await store.get_by_id(user_id)
    if user is None:
        raise UserNotFound()
    if not user.mfa_enabled:
        raise MFANotEnabled()
    if not user.hashed_password:
        raise PasswordNotSet()
    if not password_handler.verify_password(password, user.hashed_password):
        raise InvalidCredentials()
 
    totp_valid = pyotp.TOTP(user.mfa_secret).verify(totp_or_backup_code, valid_window=1)
    if not totp_valid:
        from authwarden.mfa.backup_codes import consume_backup_code
        consumed = await consume_backup_code(user, totp_or_backup_code, password_handler, store)
        if not consumed:
            raise InvalidMFACode()
 
    user.mfa_secret = None
    user.mfa_pending_secret = None
    user.mfa_enabled = False
    user.backup_codes = []
    user.updated_at = utcnow()
    await store.update(user)
    await notification_service.send_mfa_disabled(user)
 