# MFA (Multi-Factor Authentication)

TOTP-based MFA, requiring `WardenConfig.enable_mfa=True`. Each step is a separate endpoint, authenticated.

## Setup

```http
POST /auth/mfa/setup
Authorization: Bearer <access_token>
```

```json
{
  "secret": "BASE32SECRET...",
  "qr_uri": "otpauth://totp/AuthWarden:user@example.com?secret=...&issuer=AuthWarden",
  "backup_codes": ["ABCD1234", "EFGH5678", "...8 total"]
}
```

This generates a TOTP secret and 8 backup codes — **shown in plaintext exactly once, in this response.** Backup codes are stored as argon2 hashes from this point on; there's no way to retrieve them again, only regenerate via setup. Render `qr_uri` as a QR code for the user to scan into their authenticator app.

MFA is **not yet active** after setup — the secret is held as `mfa_pending_secret` until confirmed.

## Confirm

```http
POST /auth/mfa/confirm
Authorization: Bearer <access_token>
```
```json
{ "totp_code": "123456" }
```

Verifying one valid code from the authenticator app promotes the pending secret to active (`mfa_enabled=True`). From this point on, `/auth/login` requires a `totp_code`.

## Disable

```http
POST /auth/mfa/disable
Authorization: Bearer <access_token>
```
```json
{ "password": "currentpassword", "totp_or_backup_code": "123456" }
```

Requires both the account password **and** a valid TOTP code *or* an unused backup code — disabling MFA is a high-impact action, so it's gated by two factors even though the caller is already authenticated.

Using a backup code to disable MFA consumes it (single-use) — but disabling MFA also clears all remaining backup codes anyway, since they're no longer needed.

## Logging in with MFA

```json
{ "identifier": "user@example.com", "password": "...", "totp_code": "123456" }
```

Omitting `totp_code` when MFA is enabled returns `MFARequired` (403) rather than silently failing — the client knows exactly what's missing.

## TOTP timing tolerance

Verification uses `valid_window=1` — codes from the adjacent 30-second window (before or after) are also accepted. This avoids false rejections from clock drift or the brief delay between generating and submitting a code, without meaningfully weakening security.

## Errors

| Status | Exception | When |
|---|---|---|
| 409 | `MFAAlreadyEnabled` | Setup or confirm called when MFA is already active. |
| 400 | `MFANotEnabled` | Disable called when MFA isn't active. |
| 401 | `InvalidMFACode` | Wrong TOTP code, or wrong/already-used backup code. |
| 401 | `InvalidCredentials` | Wrong password on disable. |
| 400 | `PasswordNotSet` | Disable called on an account with no password (shouldn't normally happen, since MFA setup implies a password-based account). |
