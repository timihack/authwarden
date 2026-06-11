"""Login flow - suports email, username, and phone identifiers"""
from __future__ import annotations

from datetime import timedelta
import pyotp

from authwarden.authentication.jwt import JWTHandler
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import (
    AccountInactive, EmailNotVerified, InvalidCredentials,
    InvalidMFACode, MFARequired,
)
from authwarden.models.token import TokenPair
from authwarden.models.user import UserInDB, UserRead
from authwarden.session.base import AbstractSessionBackend, SessionData
from authwarden.storage.base import AbstractUserStore
from authwarden.utils import utcnow

_DUMMY_HASH = "$argon2id$v=19$m=65536,t=3,p=4$dummydummydummy$dummydummydummydummydummydummy"
 

async def _resolve_user(
  identifier: str,
  store: AbstractUserStore,
  config: WardenConfig
) -> UserInDB | None:
  """Try each configured identifier field in order, return first match."""
  for field in config.login_identifier_fields:
    user: UserInDB | None = None
    if field == "email":
      user = await store.get_by_email(identifier)
    elif field == "username":
      user = await store.get_by_username(identifier)
    elif field == "phone":
      user = await store.get_by_phone(identifier)
    if user is  not None:
      return user
  return None

async def login_flow(
    identifier: str,
    password: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
    jwt_handler: JWTHandler,
    totp_code: str | None = None,
    session_backend: AbstractSessionBackend | None = None,
    user_agent: str | None = None,
    ip_hash: str | None = None,
) -> tuple[TokenPair, UserRead]:
    """Authenticate a user and issue a token pair.
 
    The ``identifier`` is matched against ``config.login_identifier_fields``
    in order — e.g. ``["email", "username", "phone"]`` tries email first,
    then username, then phone.
 
    Args:
        identifier:   Email, username, or phone number.
        password:     Plain-text password.
        store:        User store.
        config:       Application config.
        password_handler: Password handler.
        jwt_handler:  JWT handler.
        totp_code:    TOTP code — required when MFA is enabled.
        session_backend: Optional session backend.
        user_agent:   HTTP User-Agent for session fingerprinting.
        ip_hash:      Hashed client IP for session fingerprinting.
 
    Returns:
        Tuple of (TokenPair, UserRead).
 
    Raises:
        InvalidCredentials: Identifier not found or password wrong.
        AccountInactive:    Account deactivated.
        EmailNotVerified:   Email not verified (when required).
        MFARequired:        MFA enabled but no totp_code supplied.
        InvalidMFACode:     Wrong TOTP code.
    """
    user = await _resolve_user(identifier, store, config)

    # Always run a dummy verify to normalize timing
    if user is None or not user.hashed_password:
      password_handler.verify_password(password, _DUMMY_HASH)
      raise InvalidCredentials()
    
    ok, new_hash = password_handler.verify_and_update(password, user.hashed_password)
    if not ok:
      raise InvalidCredentials()
    
    if not user.is_active:
      raise AccountInactive()
    
    if config.require_email_verification and not user.is_verified:
      raise EmailNotVerified()
    
    if config.enable_mfa and user.mfa_enabled:
      if not totp_code:
        raise MFARequired()
      if not pyotp.TOTP(user.mfa_secret).verify(totp_code):
        raise InvalidMFACode()
      
    # Silent rehash
    if new_hash:
      user.hashed_password = new_hash
      user.updated_at = utcnow()
      await store.update(user)

    pair = jwt_handler.create_token_pair(user.id, roles=user.roles, scopes=user.scopes)

    if session_backend is not None:
      await session_backend.create(SessionData(
        user_id=user.id,
        user_agent=user_agent,
        ip_hash=ip_hash,
        expires_at=utcnow() + timedelta(seconds=config.refresh_token_ttl),
      ))

    return pair, user.to_read()