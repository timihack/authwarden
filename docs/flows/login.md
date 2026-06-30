# Login

```http
POST /auth/login
```
```json
{
  "identifier": "user@example.com",
  "password": "strongpassword123",
  "totp_code": "123456"
}
```

`totp_code` is only required if the user has MFA enabled (see [MFA](../mfa.md)).

## Identifier resolution

`identifier` is matched against `WardenConfig.login_identifier_fields` **in order** — the first field type with a match wins:

```python
WardenConfig(secret_key="...", login_identifier_fields=["username", "email"])
```

With the above, `"identifier": "johndoe"` is tried as a username first; if no username matches, it's tried as an email.

## Response

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer",
  "user": { "...": "UserRead fields" }
}
```

`200 OK` on success.

## Brute force protection

Every failed attempt increments `failed_login_attempts` on the account. After `max_login_attempts` consecutive failures, the account locks for `login_lockout_duration` seconds (`AccountLocked`, status `423`). The counter resets to zero on the next successful login. Set `max_login_attempts=0` to disable lockout entirely.

A login attempt against an unknown identifier still runs a dummy password verification before returning `InvalidCredentials` — this normalizes response timing so an attacker can't distinguish "wrong password" from "no such account" by response latency.

## Errors

| Status | Exception | When |
|---|---|---|
| 401 | `InvalidCredentials` | Unknown identifier, or wrong password. |
| 423 | `AccountLocked` | Too many recent failed attempts. |
| 403 | `AccountInactive` | Account deactivated. |
| 403 | `EmailNotVerified` | `require_email_verification=True` and the account isn't verified yet. |
| 403 | `MFARequired` | MFA is enabled on the account but no `totp_code` was supplied. |
| 401 | `InvalidMFACode` | Wrong `totp_code`. |
