"""Core authentication router for authwarden.
 
build_auth_router() is called once by AuthWarden.__init__ with all the
instance-specific dependencies closed over, since each AuthWarden instance
has its own store/config/handlers. Mounted by the AuthWarden facade as
part of warden.router.
"""
from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends, Response
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from authwarden.authentication.jwt import JWTHandler
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.flows.change_password import change_password_flow
from authwarden.flows.forgot_password import forgot_password_flow
from authwarden.flows.login import login_flow
from authwarden.flows.logout import logout_flow
from authwarden.flows.refresh import refresh_flow
from authwarden.flows.register import register_flow
from authwarden.flows.resend_verification import resend_verification_flow
from authwarden.flows.reset_password import reset_password_flow
from authwarden.flows.reset_password_otp import reset_password_otp_flow
from authwarden.flows.set_password import set_password_flow
from authwarden.flows.verify_email import verify_email_flow
from authwarden.flows.verify_otp import verify_otp_flow
from authwarden.models.requests import (
  ChangePasswordRequest,
  ForgotPasswordRequest,
  LoginRequest,
  MessageResponse,
  ResendVerificationRequest,
  ResetPasswordOtpRequest,
  ResetPasswordRequest,
  SetPasswordRequest,
  TokenResponse,
  VerifyEmailRequest,
  VerifyOtpRequest,
)
from authwarden.models.token import RefreshTokenRequest, TokenPair, LogoutRequest
from authwarden.models.user import UserCreate, UserInDB, UserRead
from authwarden.notifications.service import AbstractNotificationService
from authwarden.routers._errors import handle_auth_errors
from authwarden.session.base import AbstractSessionBackend
from authwarden.storage.base import AbstractUserStore

_bearer_scheme = HTTPBearer(auto_error=True)


def build_auth_router(
  *,
  store: AbstractUserStore,
  config: WardenConfig,
  password_handler: PasswordHandler,
  jwt_handler: JWTHandler,
  notification_service: AbstractNotificationService,
  session_backend: AbstractSessionBackend | None,
  get_current_user: Callable
) -> APIRouter:
  """Build the core auth APIRouter for one AuthWarden instance.

  Args:
      store, config, password_handler, jwt_handler, notification_service:
          Instance-specific handlers built by AuthWarden.
      session_backend: Optional — None disables session creation on login.
      get_current_user: The current_user dependency built for this instance.

  Returns:
      A fully wired APIRouter with all core auth endpoints.
  """
  router = APIRouter()

  @router.post("/register", response_model=UserRead, status_code=201)
  @handle_auth_errors
  async def register(data: UserCreate) -> UserRead:
    """Register a new user account"""
    return await register_flow(
      data, store=store, config=config,
      password_handler=password_handler, notification_service=notification_service,
    )
  
  @router.post("/verify-email", response_model=UserRead)
  @handle_auth_errors
  async def verify_email(data: VerifyEmailRequest) -> UserRead:
    """Verify email using signed link token"""
    return await verify_email_flow(
      data.token, store=store, config=config,
      notification_service=notification_service
    )
  
  @router.post("/verify-otp", response_model=UserRead)
  @handle_auth_errors
  async def verify_otp(data: VerifyOtpRequest) -> UserRead:
    """Verify account using OTP"""
    return await verify_otp_flow(
      data.identifier, data.otp,
      store=store, config=config, notification_service=notification_service
    )
  
  @router.post("/resend-verification", response_model=MessageResponse)
  @handle_auth_errors
  async def resend_verification(data: ResendVerificationRequest) -> MessageResponse:
    """Resend the verification link or OTP. Always returns 200 (anti-enumeration)."""
    await resend_verification_flow(
      data.identifier, store=store, config=config, notification_service=notification_service,
    )
    return MessageResponse(detail="If this account exists, a verification message was sent.")
  
  @router.post("/login", response_model=TokenResponse)
  @handle_auth_errors
  async def login(data: LoginRequest) -> TokenResponse:
    """Authenticate and reieve and access + refresh tokeen pair."""
    pair, user = await login_flow(
      data.identifier, data.password,
      store=store, config=config, password_handler=password_handler,
      jwt_handler=jwt_handler, totp_code=data.totp_code,
      session_backend=session_backend,
    )
    return TokenResponse(
      access_token=pair.access_token, refresh_token=pair.refresh_token,
      token_type=pair.token_type, user=user
    )
  
  @router.post("/logout", status_code=204)
  @handle_auth_errors
  async def logout(
    data: LogoutRequest | None = None,
    credentials: HTTPAuthorizationCredentials = Depends(_bearer_scheme)
  ) -> Response:
    """Revoke the current access toekn (and refresh token if provided)."""
    refresh_token = data.refresh_token if data else None
    await logout_flow(credentials.credentials, jwt_handler=jwt_handler, refresh_token=refresh_token)
    return Response(status_code=204)

  @router.post("/refresh", response_model=TokenPair)
  @handle_auth_errors
  async def refresh(data: RefreshTokenRequest) -> TokenPair:
    """Exchange a valid refresh token for a new token pair."""
    return await refresh_flow(data.refresh_token, store=store, config=config, jwt_handler=jwt_handler)
  
  @router.post("/forgot-password", response_model=MessageResponse)
  @handle_auth_errors
  async def forgot_password(data: ForgotPasswordRequest) -> MessageResponse:
    """Request a password rest lonk or OTP. Always returns 200 (anti-enumeration)."""
    await forgot_password_flow(
      data.identifier, store=store, config=config, notification_service=notification_service
    )
    return MessageResponse(detail="If this account exists, a reset message was sent.")
  
  @router.post("/reset-password", response_model=MessageResponse)
  @handle_auth_errors
  async def reset_password(data: ResetPasswordRequest) -> MessageResponse:
    """Reset password using a signed link token"""
    await reset_password_flow(
      data.token, data.new_password, store=store, config=config,
      password_handler=password_handler, notification_service=notification_service,
    )
    return MessageResponse(details="Password reset successfully.")

  @router.post("reset-password-otp", response_model=MessageResponse)
  @handle_auth_errors
  async def reset_password_otp(data: ResetPasswordOtpRequest) -> MessageResponse:
    """Reset password using OTP code"""
    await reset_password_otp_flow(
      data.identifier, data.otp, data.new_password, store=store, config=config,
      password_handler=password_handler, notification_service=notification_service,
    )
    return MessageResponse(detail="Password reset successfully.")
  
  @router.post("/change-password", response_model=TokenPair)
  @handle_auth_errors
  async def change_password(
    data: ChangePasswordRequest,
    user: UserInDB = Depends(get_current_user),
  ) -> TokenPair:
    """Change password for the authenticated user. Returns a fresh token pair."""
    return await change_password_flow(
      user.id, data.current_password, data.new_password,
      store=store, config=config, password_handler=password_handler,
      jwt_handler=jwt_handler, notification_service=notification_service
    )
  
  @router.post("/set-password", response_model=MessageResponse)
  @handle_auth_errors
  async def set_password(
    data: SetPasswordRequest,
    user: UserInDB = Depends(get_current_user),
  ) -> MessageResponse:
    """Add a password login method to an OAuth-only account."""
    await set_password_flow(
      user.id, data.new_password, store=store, config=config,
      password_handler=password_handler, notification_service=notification_service
    )

  return router
  
