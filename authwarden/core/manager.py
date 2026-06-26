"""AuthWarden — the top-level facade for authwarden.
 
Wires together password hashing, JWT, sessions, email/SMS notifications,
OAuth providers, and all flows behind a single object. Mount warden.router
on a FastAPI app and use warden.current_user / warden.require_roles /
warden.require_scopes as Depends() factories for your own routes.
"""
from __future__ import annotations

from typing import Callable

from fastapi import APIRouter

from authwarden.authentication.jwt import AbstractTokenBlacklist, JWTHandler, MemoryTokenBlacklist
from authwarden.authentication.oauth import OAuthProviderBase, build_oauth_provider
from authwarden.authentication.oauth_state import AbstractOAuthStateStore, MemoryOAuthStateStore
from authwarden.authentication.password import PasswordHandler
from authwarden.core.config import WardenConfig
from authwarden.dependencies.current_user import build_get_current_user
from authwarden.dependencies.permissions import build_require_roles, build_require_scopes
from authwarden.email.base import AbstractEmailBackend
from authwarden.email.console import ConsoleEmailBackend
from authwarden.email.smtp import SmtpEmailBackend
from authwarden.email.templates import EmailTemplates
from authwarden.notifications.service import AbstractNotificationService, NotificationService
from authwarden.routers.auth import build_auth_router
from authwarden.routers.mfa import build_mfa_router
from authwarden.routers.oauth import build_oauth_router
from authwarden.session.base import AbstractSessionBackend
from authwarden.session.memory import MemorySessionBackend
from authwarden.sms.base import AbstractSmsBackend
from authwarden.sms.templates import SmsTemplates
from authwarden.storage.base import AbstractUserStore


def _build_email_backend(config: WardenConfig) ->AbstractEmailBackend:
  """Build the default email backend from config.

  Only "console" and "smtp" are auto-selectable from config — SendGrid
  and Mailgun have no static credentials format that fits a single
  config field cleanly, so pass them explicitly via the email_backend
  constructor argument instead.
  """
  if config.email_backend == "smtp":
    return SmtpEmailBackend.from_config(config)
  return ConsoleEmailBackend()


def _build_session_backend(config: WardenConfig) -> AbstractSessionBackend | None:
  """Build a default session backend from config, or None if disabled"""
  if config.session_backend == "memory":
    return MemorySessionBackend()
  if config.session_backend == "redis":
    if not config.redis_url:
      raise ValueError("session_backend='redis' requires redis_url to be set")
    from authwarden.session.redis import RedisSessionBackend
    return RedisSessionBackend(config.redis_url)
  return None


def _build_oauth_providers(config: WardenConfig) -> dict[str, OAuthProviderBase]:
  """Build all configured and enabled OAuth providers from config."""
  providers: dict[str, OAuthProviderBase] = {}
  for name, provider_config in config.oauth_providers.items():
    if not provider_config.enabled:
      continue
    providers[name] = build_oauth_provider(
      name, provider_config,
      apple_team_id=config.apple_team_id,
      apple_key_id=config.apple_key_id,
      apple_private_key_pem=config.apple_private_key_pem,
    )
  return providers


class AuthWarden:
  """Top-level facade for authwarden.

  Usage::

      warden = AuthWarden(
          config=WardenConfig(secret_key="..."),
          user_store=MyUserStore(),
      )
      app.include_router(warden.router, prefix="/auth", tags=["auth"])

      @app.get("/profile")
      async def profile(user=Depends(warden.current_user)):
          return user

      @app.delete("/admin/users")
      async def delete_user(user=Depends(warden.require_roles("admin"))):
          ...
  """

  def __init__(
    self,
    config: WardenConfig,
    user_store: AbstractUserStore,
    *,
    email_backend: AbstractEmailBackend | None = None,
    sms_backend: AbstractSmsBackend | None = None,
    notification_service: AbstractNotificationService | None = None,
    email_templates: EmailTemplates | None = None,
    sms_templates: SmsTemplates | None = None,
    password_handler: PasswordHandler | None = None,
    token_blacklist: AbstractTokenBlacklist | None = None,
    session_backend: AbstractSessionBackend | None = None,
    oauth_state_store: AbstractOAuthStateStore | None = None,
  ) -> None:
    """Construct an AuthWarden instance.

    Args:
        config:     Application WardenConfig.
        user_store: Consumer's AbstractUserStore implementation.
        email_backend, sms_backend: Override the auto-selected backends.
            Required for SendGrid, Mailgun, Twilio, or AWS SNS — these
            have no config-driven auto-selection, pass an instance directly.
        notification_service: Fully override notification routing.
        email_templates, sms_templates: Override default copy.
        password_handler: Override the default PasswordHandler.
        token_blacklist:  Override the default MemoryTokenBlacklist
            (pass a RedisTokenBlacklist for multi-process deployments).
        session_backend:  Override the config-driven session backend.
        oauth_state_store: Override the default MemoryOAuthStateStore
            (use a Redis-backed implementation for multi-process deployments).
    """
    self.config = config
    self.store = user_store

    self.password_handler = password_handler or PasswordHandler(config)
    self.jwt_handler = JWTHandler(config, blacklist=token_blacklist or MemoryTokenBlacklist())
    self.session_backend = session_backend if session_backend is not None else _build_session_backend(config)

    resolved_email_backend = email_backend or _build_email_backend(config)
    self.notification_service = notification_service or NotificationService(
      config=config,
      email_backend=email_backend,
      sms_backend=sms_backend,
      email_templates=email_templates,
      sms_templates=sms_templates,
    )

    self.oauth_state_store = oauth_state_store or MemoryOAuthStateStore()
    self.oauth_providers = _build_oauth_providers(config)

    # Dependecy factories - built once, reused accross all routes
    self._get_current_user = build_get_current_user(self.jwt_handler, self.store)
    self._require_roles_factory = build_require_roles(self.jwt_handler)
    self._require_scopes_factory = build_require_scopes(self.jwt_handler)

    self._router = self._build_router()

  def _build_router(self) -> APIRouter:
    """Assemble the combined router from auth, mfa, and oauth sub-routers."""
    router = APIRouter()
    router.include_router(build_auth_router(
        store=self.store, config=self.config, password_handler=self.password_handler,
        jwt_handler=self.jwt_handler, notification_service=self.notification_service,
        session_backend=self.session_backend, get_current_user=self._get_current_user,
    ))
    router.include_router(build_mfa_router(
        store=self.store, config=self.config, password_handler=self.password_handler,
        notification_service=self.notification_service, get_current_user=self._get_current_user,
    ))
    router.include_router(build_oauth_router(
        store=self.store, config=self.config, jwt_handler=self.jwt_handler,
        notification_service=self.notification_service, providers=self.oauth_providers,
        state_store=self.oauth_state_store, get_current_user=self._get_current_user,
    ))
    return router

  @property
  def router(self) -> APIRouter:
    """The combined FastAPI router — mount with app.include_router(warden.router, prefix='/auth')."""
    return self._router
  
  @property
  def current_user(self) -> Callable:
    """Depends()-compatible callable resolving the authenticated user.

    Usage: ``user=Depends(warden.current_user)``
    """
    return self._get_current_user
  
  def require_roles(self, *roles: str, require_all: bool = False) -> Callable:
      """Build a Depends()-compatible role-check dependency.

      Args:
          roles:       Role(s) to require.
          require_all: If True, all roles required; if False, any one suffices.

      Usage: ``Depends(warden.require_roles("admin"))``
      """
      return self._require_roles_factory(*roles, require_all=require_all)

  def require_scopes(self, *scopes: str, require_all: bool = False) -> Callable:
      """Build a Depends()-compatible scope-check dependency.

      Args:
          scopes:      Scope(s) to require.
          require_all: If True, all scopes required; if False, any one suffices.

      Usage: ``Depends(warden.require_scopes("write"))``
      """
      return self._require_scopes_factory(*scopes, require_all=require_all)

