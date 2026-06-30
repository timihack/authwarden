# Password Reset & Change

## Forgot password

```http
POST /auth/forgot-password
```
```json
{ "identifier": "user@example.com" }
```

Like resend-verification, this **always returns 200** regardless of whether the identifier exists — anti-enumeration by design. Rate-limited to one request per 60 seconds per account.

Depending on `WardenConfig.password_reset_method`:
- **`"link"`** (default): an `itsdangerous`-signed link is emailed, expiring after `password_reset_ttl` seconds
- **`"otp"`**: a numeric OTP is sent via the configured `password_reset_channels`

## Reset — link mode

```http
POST /auth/reset-password
```
```json
{ "token": "...", "new_password": "newstrongpassword" }
```

## Reset — OTP mode

```http
POST /auth/reset-password-otp
```
```json
{ "identifier": "user@example.com", "otp": "123456", "new_password": "newstrongpassword" }
```

Same attempt-limiting behavior as OTP verification — wrong guesses count toward `max_otp_attempts`, after which the OTP is invalidated.

Both reset endpoints reject the new password if it's identical to the current one (`SamePassword`), and both send a confirmation notification once the password actually changes.

## Change password (authenticated)

```http
POST /auth/change-password
Authorization: Bearer <access_token>
```
```json
{ "current_password": "oldpassword", "new_password": "newstrongpassword" }
```

Returns a **fresh token pair** — the caller's session stays valid immediately after changing their own password, without needing to log in again.

## Set password (OAuth-only accounts)

```http
POST /auth/set-password
Authorization: Bearer <access_token>
```
```json
{ "new_password": "newstrongpassword" }
```

For accounts created via OAuth with no password set (`hashed_password is None`). Lets a user add password-based login as a second method alongside their social login. Raises `PasswordAlreadySet` if the account already has a password — use `/auth/change-password` instead in that case.

## Errors

| Status | Exception | When |
|---|---|---|
| 400 | `InvalidToken` | Bad link signature, wrong OTP, or hash mismatch. |
| 400 | `TokenExpired` | Link/OTP TTL elapsed or OTP attempts exhausted. |
| 400 | `TokenAlreadyUsed` | Link-mode reset token already consumed (single-use enforcement). |
| 422 | `SamePassword` | New password matches the current one. |
| 422 | `WeakPassword` | Fails policy. |
| 429 | `RateLimited` | Forgot-password requested too soon. |
| 401 | `InvalidCredentials` | Wrong `current_password` on change-password. |
| 400 | `PasswordNotSet` | Change-password called on an OAuth-only account — use set-password instead. |
| 400 | `PasswordAlreadySet` | Set-password called on an account that already has one. |
