"""NotificationService — central hub for all authwarden notifications.

Routes messages to email and/or SMS based on config and what channels
the user has available. Flows call this instead of email/sms backends directly.

Consumers can implement their own notification service by satisfying the
AbstractNotificationService protocol — useful for custom routing logic,
push notifications, webhooks, etc.::

    class MyNotificationService:
        async def send_verification_otp(self, user, otp): ...
        # implement remaining methods

    warden = AuthWarden(..., notification_service=MyNotificationService())
"""
from __future__ import annotations
from typing import Protocol, runtime_checkable

from authwarden.core.config import WardenConfig
from authwarden.email.base import AbstractEmailBackend, EmailMessage
from authwarden.email.templates import EmailTemplates
from authwarden.models.user import UserInDB
from authwarden.sms.base import AbstractSmsBackend, SmsMessage
from authwarden.sms.templates import SmsTemplates


@runtime_checkable
class AbstractNotificationService(Protocol):
    """Protocol for notification services.

    Implement all methods to provide a custom notification service.
    Structural subtyping — no inheritance required.
    """
    async def send_verification_link(self, user: UserInDB, link: str) -> None: ...
    async def send_verification_otp(self, user: UserInDB, otp: str) -> None: ...
    async def send_welcome(self, user: UserInDB) -> None: ...
    async def send_password_reset_link(self, user: UserInDB, link: str) -> None: ...
    async def send_password_reset_otp(self, user: UserInDB, otp: str) -> None: ...
    async def send_password_changed(self, user: UserInDB) -> None: ...
    async def send_mfa_enabled(self, user: UserInDB) -> None: ...
    async def send_mfa_disabled(self, user: UserInDB) -> None: ...


class NotificationService:
    """Default notification service — routes email and SMS based on config.

    Usage::

        service = NotificationService(
            config=config,
            email_backend=SmtpEmailBackend.from_config(config),
            sms_backend=TwilioSmsBackend(sid, token, from_number),
        )

    The service respects ``config.verification_channels`` and
    ``config.password_reset_channels`` to decide which channels to use.
    It gracefully skips channels the user doesn't have (e.g. no phone → skip SMS).
    """

    def __init__(
        self,
        config: WardenConfig,
        email_backend: AbstractEmailBackend | None = None,
        sms_backend: AbstractSmsBackend | None = None,
        email_templates: EmailTemplates | None = None,
        sms_templates: SmsTemplates | None = None,
    ) -> None:
        self._config = config
        self._email = email_backend
        self._sms = sms_backend
        self._et = email_templates or EmailTemplates()
        self._st = sms_templates or SmsTemplates()

    # ── Internal helpers ──────────────────────────────────────────

    async def _send_email(self, to: str, subject: str, plain: str, html: str) -> None:
        if self._email:
            await self._email.send(EmailMessage(to=to, subject=subject, plain_text=plain, html=html))

    async def _send_sms(self, to: str, body: str) -> None:
        if self._sms:
            await self._sms.send(SmsMessage(to=to, body=body))

    async def _dispatch(
        self,
        user: UserInDB,
        channels: list[str],
        email_fn,   # () -> (subject, plain, html)
        sms_fn,     # () -> body str
    ) -> None:
        """Send to all configured channels the user has available."""
        for ch in channels:
            if ch == "email" and user.email:
                subject, plain, html = email_fn()
                await self._send_email(user.email, subject, plain, html)
            elif ch == "sms" and user.phone_number:
                body = sms_fn()
                await self._send_sms(user.phone_number, body)

    # ── Verification ──────────────────────────────────────────────

    async def send_verification_link(self, user: UserInDB, link: str) -> None:
        """Send email verification link. Always via email channel."""
        if user.email:
            s, p, h = self._et.verify_email(user, link)
            await self._send_email(user.email, s, p, h)

    async def send_verification_otp(self, user: UserInDB, otp: str) -> None:
        """Send verification OTP via configured verification_channels."""
        mins = max(1, self._config.otp_ttl // 60)
        await self._dispatch(
            user, self._config.verification_channels,
            email_fn=lambda: self._et.verify_otp(user, otp, mins),
            sms_fn=lambda: self._st.verify_otp(user, otp, mins),
        )

    async def send_welcome(self, user: UserInDB) -> None:
        """Send welcome notification — email preferred, SMS fallback."""
        if user.email:
            s, p, h = self._et.welcome(user)
            await self._send_email(user.email, s, p, h)
        elif user.phone_number:
            await self._send_sms(user.phone_number, self._st.welcome(user))

    # ── Password ──────────────────────────────────────────────────

    async def send_password_reset_link(self, user: UserInDB, link: str) -> None:
        """Send password reset link. Always via email."""
        if user.email:
            expires_hours = max(1, self._config.password_reset_ttl // 3600)
            s, p, h = self._et.password_reset(user, link, expires_hours)
            await self._send_email(user.email, s, p, h)

    async def send_password_reset_otp(self, user: UserInDB, otp: str) -> None:
        """Send password reset OTP via configured password_reset_channels."""
        mins = max(1, self._config.otp_ttl // 60)
        await self._dispatch(
            user, self._config.password_reset_channels,
            email_fn=lambda: self._et.password_reset_otp(user, otp, mins),
            sms_fn=lambda: self._st.password_reset_otp(user, otp, mins),
        )

    async def send_password_changed(self, user: UserInDB) -> None:
        """Send password changed confirmation — email preferred, SMS fallback."""
        if user.email:
            s, p, h = self._et.password_changed(user)
            await self._send_email(user.email, s, p, h)
        elif user.phone_number:
            await self._send_sms(user.phone_number, self._st.password_changed(user))

    # ── MFA ───────────────────────────────────────────────────────

    async def send_mfa_enabled(self, user: UserInDB) -> None:
        if user.email:
            s, p, h = self._et.mfa_enabled(user)
            await self._send_email(user.email, s, p, h)
        elif user.phone_number:
            await self._send_sms(user.phone_number, self._st.mfa_enabled(user))

    async def send_mfa_disabled(self, user: UserInDB) -> None:
        if user.email:
            s, p, h = self._et.mfa_disabled(user)
            await self._send_email(user.email, s, p, h)
        elif user.phone_number:
            await self._send_sms(user.phone_number, self._st.mfa_disabled(user))