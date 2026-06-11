"""Email templates for all authwarden flows.

Override by subclassing and passing your instance to NotificationService::

    class MyTemplates(EmailTemplates):
        def verify_otp(self, user, otp, expires_minutes):
            return "Your code", f"Code: {otp}", f"<b>{otp}</b>"

Each method returns ``(subject, plain_text, html)``.
"""
from __future__ import annotations
from authwarden.models.user import UserInDB


class EmailTemplates:
    """Default email templates. All methods return (subject, plain_text, html)."""

    # ── Verification — link ───────────────────────────────────────

    def verify_email(self, user: UserInDB, link: str) -> tuple[str, str, str]:
        name = user.full_name or user.email
        subject = "Verify your email address"
        plain = (f"Hi {name},\n\nVerify your email:\n{link}\n\n"
                 f"This link expires in 24 hours.\n\nIgnore if you did not register.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Verify your email</h2><p>Hi {name},</p>'
                f'<p>Click below to verify your email and activate your account.</p>'
                f'<p><a href="{link}" style="background:#2563eb;color:#fff;padding:12px 24px;'
                f'border-radius:6px;text-decoration:none;font-weight:600">Verify Email</a></p>'
                f'<p style="color:#666;font-size:14px">Expires in 24 hours. '
                f'If you did not register, ignore this email.</p>'
                f'<p style="color:#999;font-size:12px"><a href="{link}">{link}</a></p></body>')
        return subject, plain, html

    # ── Verification — OTP ────────────────────────────────────────

    def verify_otp(self, user: UserInDB, otp: str, expires_minutes: int) -> tuple[str, str, str]:
        """OTP-based email verification."""
        name = user.full_name or user.email
        subject = "Your verification code"
        plain = (f"Hi {name},\n\nYour verification code is:\n\n{otp}\n\n"
                 f"This code expires in {expires_minutes} minutes.\n\n"
                 f"Do not share this code. Ignore if you did not register.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Your verification code</h2><p>Hi {name},</p>'
                f'<p>Enter this code to verify your account:</p>'
                f'<p style="font-size:36px;font-weight:700;letter-spacing:8px;'
                f'color:#2563eb;text-align:center;padding:24px 0">{otp}</p>'
                f'<p style="color:#666;font-size:14px">Expires in {expires_minutes} minutes. '
                f'Do not share this code.</p></body>')
        return subject, plain, html

    # ── Welcome ───────────────────────────────────────────────────

    def welcome(self, user: UserInDB) -> tuple[str, str, str]:
        name = user.full_name or user.email
        subject = "Welcome — your account is ready"
        plain = f"Hi {name},\n\nYour account is now active. You can log in and get started."
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Your account is ready ✓</h2><p>Hi {name},</p>'
                f'<p>Your account is now active. Welcome aboard!</p></body>')
        return subject, plain, html

    # ── Password reset — link ─────────────────────────────────────

    def password_reset(self, user: UserInDB, link: str, expires_hours: int) -> tuple[str, str, str]:
        name = user.full_name or user.email
        subject = "Reset your password"
        plain = (f"Hi {name},\n\nReset your password:\n{link}\n\n"
                 f"Expires in {expires_hours} hour(s). Ignore if you did not request this.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Reset your password</h2><p>Hi {name},</p>'
                f'<p>Click below to choose a new password.</p>'
                f'<p><a href="{link}" style="background:#2563eb;color:#fff;padding:12px 24px;'
                f'border-radius:6px;text-decoration:none;font-weight:600">Reset Password</a></p>'
                f'<p style="color:#666;font-size:14px">Expires in {expires_hours} hour(s). '
                f'Ignore if you did not request this.</p>'
                f'<p style="color:#999;font-size:12px"><a href="{link}">{link}</a></p></body>')
        return subject, plain, html

    # ── Password reset — OTP ──────────────────────────────────────

    def password_reset_otp(self, user: UserInDB, otp: str, expires_minutes: int) -> tuple[str, str, str]:
        """OTP-based password reset."""
        name = user.full_name or user.email
        subject = "Your password reset code"
        plain = (f"Hi {name},\n\nYour password reset code is:\n\n{otp}\n\n"
                 f"Expires in {expires_minutes} minutes. Do not share this code.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Your password reset code</h2><p>Hi {name},</p>'
                f'<p>Enter this code to reset your password:</p>'
                f'<p style="font-size:36px;font-weight:700;letter-spacing:8px;'
                f'color:#2563eb;text-align:center;padding:24px 0">{otp}</p>'
                f'<p style="color:#666;font-size:14px">Expires in {expires_minutes} minutes. '
                f'Do not share this code.</p></body>')
        return subject, plain, html

    # ── Password changed ──────────────────────────────────────────

    def password_changed(self, user: UserInDB) -> tuple[str, str, str]:
        name = user.full_name or user.email
        subject = "Your password was changed"
        plain = (f"Hi {name},\n\nYour password was recently changed.\n\n"
                 f"If you made this change, no action needed.\n\n"
                 f"If you did NOT change your password, contact support immediately.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Your password was changed</h2><p>Hi {name},</p>'
                f'<p>Your password was recently changed. If you made this change, no action needed.</p>'
                f'<p style="background:#fef3c7;border-left:4px solid #f59e0b;padding:12px 16px;'
                f'border-radius:4px">If you did <strong>not</strong> make this change, '
                f'contact support immediately.</p></body>')
        return subject, plain, html

    # ── MFA ───────────────────────────────────────────────────────

    def mfa_enabled(self, user: UserInDB) -> tuple[str, str, str]:
        name = user.full_name or user.email
        subject = "Two-factor authentication enabled"
        plain = (f"Hi {name},\n\n2FA has been enabled on your account.\n\n"
                 f"Contact support if you did not do this.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Two-factor authentication enabled ✓</h2><p>Hi {name},</p>'
                f'<p>2FA is now active. Your account is more secure.</p>'
                f'<p style="color:#666;font-size:14px">Contact support if you did not do this.</p></body>')
        return subject, plain, html

    def mfa_disabled(self, user: UserInDB) -> tuple[str, str, str]:
        name = user.full_name or user.email
        subject = "Two-factor authentication disabled"
        plain = (f"Hi {name},\n\n2FA has been disabled on your account.\n\n"
                 f"Your account is now protected by password only.\n\n"
                 f"If you did not do this, contact support and change your password immediately.")
        html = (f'<body style="font-family:sans-serif;max-width:560px;margin:0 auto;padding:24px">'
                f'<h2>Two-factor authentication disabled</h2><p>Hi {name},</p>'
                f'<p>2FA has been disabled. Your account is password-only.</p>'
                f'<p style="background:#fee2e2;border-left:4px solid #ef4444;padding:12px 16px;'
                f'border-radius:4px"><strong>Security warning:</strong> if you did not disable 2FA, '
                f'contact support and change your password immediately.</p></body>')
        return subject, plain, html