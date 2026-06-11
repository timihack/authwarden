"""SMS templates for authwarden flows.

Override any method by subclassing SmsTemplates::

    class MySmsTemplates(SmsTemplates):
        def verify_otp(self, user, otp, expires_minutes):
            return f"[MyApp] Your code: {otp}. Valid {expires_minutes}min."

Each method returns a plain string (the SMS body).
Keep messages under 160 chars for a single SMS segment.
"""
from __future__ import annotations
from authwarden.models.user import UserInDB


class SmsTemplates:
    """Default SMS templates. Subclass and override any method to customise."""

    def verify_otp(self, user: UserInDB, otp: str, expires_minutes: int) -> str:
        return f"Your verification code is {otp}. Expires in {expires_minutes} min. Do not share this code."

    def password_reset_otp(self, user: UserInDB, otp: str, expires_minutes: int) -> str:
        return f"Your password reset code is {otp}. Expires in {expires_minutes} min. If you did not request this, ignore."

    def welcome(self, user: UserInDB) -> str:
        name = user.full_name or "there"
        return f"Welcome {name}! Your account is now active."

    def password_changed(self, user: UserInDB) -> str:
        return "Your password was changed. If you did not do this, contact support immediately."

    def mfa_enabled(self, user: UserInDB) -> str:
        return "Two-factor authentication has been enabled on your account."

    def mfa_disabled(self, user: UserInDB) -> str:
        return "Two-factor authentication was disabled. Contact support if you did not do this."