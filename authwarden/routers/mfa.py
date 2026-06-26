"""MFA router authwarden - etup, confirm, disable."""
from __future__ import annotations

from typing import Callable

from fastapi import APIRouter, Depends

from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.mfa.totp import MFASetupResult, confirm_mfa_flow, disable_mfa_flow, setup_mfa_flow
from authwarden.models.requests import MessageResponse, MfaConfirmRequest, MfaDisableRequest
from authwarden.models.user import UserInDB
from authwarden.notifications.service import AbstractNotificationService
from authwarden.routers._errors import handle_auth_errors
from authwarden.storage.base import AbstractUserStore


def build_mfa_router(
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    password_handler: PasswordHandler,
    notification_service: AbstractNotificationService,
    get_current_user: Callable,
) -> APIRouter:
  """Build the MFA APIRouter for one AuthWarden instance.

  Returns:
      APIRouter with /mfa/setup, /mfa/confirm, /mfa/disable mounted.
  """
  router = APIRouter(prefix="/mfa")

  @router.post("/setup", response_model=MFASetupResult)
  @handle_auth_errors
  async def setup(user: UserInDB = Depends(get_current_user)) -> MFASetupResult:
    """Generate a TOTP and backup codes. Not active until confirm."""
    return await setup_mfa_flow(
      user.id, store=store, config=config, password_handler=password_handler
    )
  
  @router.post("/confirm", response_model=MessageResponse)
  @handle_auth_errors
  async def confirm(
    data: MfaConfirmRequest, user: UserInDB = Depends(get_current_user),
  ) -> MessageResponse:
    """Confirm MFA setup with the first TOTP code, activating MFA."""
    await confirm_mfa_flow(
      user.id, data.totp_code, store=store, notification_service=notification_service,
    )
    return MessageResponse(detail="MFA enabled sucessfully.")
  
  @router.post("/disable", response_model=MessageResponse)
  @handle_auth_errors
  async def disable(
    data: MfaDisableRequest, user: UserInDB = Depends(get_current_user),
  ):
    """Disable MFA - require password + TOTP or backup code."""
    await disable_mfa_flow(
      user.id, data.password, data.totp_or_backup_code,
      store=store, password_handler=password_handler,
      notification_service=notification_service
    )
    return MessageResponse(detail="MFA disable successfully.")
  
  return router
