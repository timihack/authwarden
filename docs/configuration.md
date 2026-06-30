# Configuration Reference

Every behavioral switch in authwarden lives on `WardenConfig`. It's a `pydantic-settings` model — every field can also be set via environment variable (uppercase, matching the field name) or a `.env` file, in addition to passing it directly.

```python
from authwarden import WardenConfig

config = WardenConfig(secret_key="...", require_email_verification=False)
```

```bash
# .env file works too
SECRET_KEY=...
REQUIRE_EMAIL_VERIFICATION=false
```

Only `secret_key` is required — everything else has a sensible default.

## JWT

| Field | Type | Default | Description |
|---|---|---|---|
| `secret_key` | `str` | **required** | Signs and verifies all JWTs. Use a real random secret of at least 32 bytes in production. |
| `algorithm` | `str` | `"HS256"` | JWT signing algorithm, passed to PyJWT. |
| `access_token_ttl` | `int` | `900` (15 min) | Access token lifetime, in seconds. |
| `refresh_token_ttl` | `int` | `604800` (7 days) | Refresh token lifetime, in seconds. |
| `enable_refresh_rotation` | `bool` | `True` | When `True`, every `/auth/refresh` call blacklists the old refresh token and issues a new one — a stolen refresh token can only be used once before it's invalidated. |

## Passwords

| Field | Type | Default | Description |
|---|---|---|---|
| `password_hasher` | `"argon2"` \| `"bcrypt"` | `"argon2"` | Algorithm used by `PasswordHandler`. |
| `min_password_length` | `int` | `8` | Minimum password length enforced at registration, reset, and change. |
| `require_password_uppercase` | `bool` | `False` | Require at least one uppercase letter. |
| `require_password_digit` | `bool` | `False` | Require at least one digit. |
| `require_password_special` | `bool` | `False` | Require at least one non-alphanumeric character. |

All policy violations are reported together in a single error, not one-at-a-time.

## Brute Force Protection

| Field | Type | Default | Description |
|---|---|---|---|
| `max_login_attempts` | `int` | `5` | Failed logins before lockout. Set to `0` to disable lockout entirely. |
| `login_lockout_duration` | `int` | `900` (15 min) | How long an account stays locked after hitting the limit, in seconds. |
| `max_otp_attempts` | `int` | `5` | Wrong OTP guesses before the OTP is invalidated and a new one must be requested. Set to `0` to disable. |

The failed-attempt counter resets to zero on any successful login.

## Login Identifiers

| Field | Type | Default | Description |
|---|---|---|---|
| `login_identifier_fields` | `list["email" \| "username" \| "phone"]` | `["email"]` | Fields tried, in order, when resolving the `identifier` passed to `/auth/login`. The first field type with a match wins. |

```python
# Try username first, fall back to email
WardenConfig(secret_key="...", login_identifier_fields=["username", "email"])
```

## Email Verification

| Field | Type | Default | Description |
|---|---|---|---|
| `verification_method` | `"link"` \| `"otp"` | `"link"` | Signed-link verification, or a numeric OTP. |
| `verification_channels` | `list["email" \| "sms"]` | `["email"]` | Where the OTP is sent (link mode always uses email — there's no "SMS link" concept). Set to `["email", "sms"]` to send to both. |
| `otp_length` | `int` | `6` | Number of digits in generated OTPs (verification *and* password reset). |
| `otp_ttl` | `int` | `600` (10 min) | OTP expiry, in seconds. |
| `email_verification_ttl` | `int` | `86400` (24h) | Link-mode verification token expiry, in seconds. |
| `resend_verification_cooldown` | `int` | `60` | Minimum seconds between resend requests. |
| `require_email_verification` | `bool` | `True` | When `False`, new accounts are immediately active and verified — no verification step at all. |

## Password Reset

| Field | Type | Default | Description |
|---|---|---|---|
| `password_reset_method` | `"link"` \| `"otp"` | `"link"` | Same choice as verification, independently configurable. |
| `password_reset_channels` | `list["email" \| "sms"]` | `["email"]` | Same channel logic as verification. |
| `password_reset_ttl` | `int` | `3600` (1h) | Link-mode reset token expiry, in seconds. |

## Registration

| Field | Type | Default | Description |
|---|---|---|---|
| `allow_registration` | `bool` | `True` | Currently informational — gate registration yourself at the route level if you need to disable it (e.g. invite-only apps). |

## Email Backend

| Field | Type | Default | Description |
|---|---|---|---|
| `email_backend` | `"smtp"` \| `"console"` | `"console"` | Auto-selected backend. **SendGrid and Mailgun aren't selectable via config** — pass an instance directly to `AuthWarden(email_backend=...)` instead. See [Notifications → Email](notifications/email.md). |
| `smtp_host` | `str` | `"localhost"` | |
| `smtp_port` | `int` | `587` | |
| `smtp_username` | `str \| None` | `None` | |
| `smtp_password` | `str \| None` | `None` | |
| `smtp_use_tls` | `bool` | `True` | |
| `emails_from_name` | `str` | `"AuthWarden"` | |
| `emails_from_address` | `str` | `"noreply@example.com"` | |

## SMS Credentials

These are credentials only — there's no `sms_backend` selector field. Build the backend yourself and pass it to `AuthWarden(sms_backend=...)`. See [Notifications → SMS](notifications/sms.md).

| Field | Type | Default |
|---|---|---|
| `twilio_account_sid` | `str \| None` | `None` |
| `twilio_auth_token` | `str \| None` | `None` |
| `twilio_from_number` | `str \| None` | `None` |
| `aws_sns_region` | `str \| None` | `None` |
| `aws_sns_sender_id` | `str \| None` | `None` |

## Sessions

| Field | Type | Default | Description |
|---|---|---|---|
| `session_backend` | `"memory"` \| `"redis"` \| `None` | `None` | When set, `login_flow` creates a `SessionData` record on every successful login (for fingerprinting/audit purposes — not required for normal JWT auth to function). |
| `redis_url` | `str \| None` | `None` | Required if `session_backend="redis"`. |

## MFA

| Field | Type | Default | Description |
|---|---|---|---|
| `enable_mfa` | `bool` | `False` | When `True`, users with `mfa_enabled=True` on their account must supply a valid `totp_code` at login. |
| `mfa_issuer_name` | `str` | `"AuthWarden"` | Shown in the user's authenticator app next to the generated TOTP entry. |

## OAuth

| Field | Type | Default | Description |
|---|---|---|---|
| `oauth_providers` | `dict[str, OAuthProviderConfig]` | `{}` | Keyed by provider name (`"google"`, `"github"`, etc.). See [OAuth Overview](oauth/overview.md). |
| `auto_link_by_email` | `bool` | `True` | When a social login's email matches an existing local account, link automatically. When `False`, raises `EmailAlreadyRegistered` instead — the user must log in with their password first, then connect the provider explicitly. |
| `apple_team_id` | `str \| None` | `None` | Required only for the `"apple"` provider. |
| `apple_key_id` | `str \| None` | `None` | Required only for the `"apple"` provider. |
| `apple_private_key_pem` | `str \| None` | `None` | Required only for the `"apple"` provider — the `.p8` private key content. |

### `OAuthProviderConfig`

```python
class OAuthProviderConfig(BaseModel):
    client_id: str
    client_secret: str
    redirect_uri: str
    scopes: list[str] = []      # falls back to the provider's sane default scopes if empty
    enabled: bool = True        # set False to keep credentials configured but the route disabled
```

## Frontend URLs

Used to build the links sent in verification/reset emails — these point at *your* frontend, not authwarden's API.

| Field | Type | Default | Description |
|---|---|---|---|
| `frontend_base_url` | `str` | `"http://localhost:3000"` | |
| `verify_email_path` | `str` | `"/auth/verify-email"` | Appended to `frontend_base_url`, with `?token=...` added. |
| `reset_password_path` | `str` | `"/auth/reset-password"` | Same pattern. |
