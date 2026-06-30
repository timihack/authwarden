# API Reference

All 20 endpoints exposed by `warden.router`, organized by sub-router. Mount with whatever prefix you like — examples below assume `prefix="/auth"` as in the [Quickstart](quickstart.md).

## Auth

| Method | Path | Auth required | Description |
|---|---|---|---|
| POST | `/register` | No | [Registration](flows/registration.md) |
| POST | `/verify-email` | No | [Verification — link mode](flows/verification.md) |
| POST | `/verify-otp` | No | [Verification — OTP mode](flows/verification.md) |
| POST | `/resend-verification` | No | [Verification](flows/verification.md) |
| POST | `/login` | No | [Login](flows/login.md) |
| POST | `/logout` | Yes | [Logout](flows/logout-refresh.md) |
| POST | `/refresh` | No¹ | [Refresh](flows/logout-refresh.md) |
| POST | `/forgot-password` | No | [Password reset](flows/password-reset.md) |
| POST | `/reset-password` | No | [Password reset — link mode](flows/password-reset.md) |
| POST | `/reset-password-otp` | No | [Password reset — OTP mode](flows/password-reset.md) |
| POST | `/change-password` | Yes | [Password reset](flows/password-reset.md) |
| POST | `/set-password` | Yes | [Password reset — OAuth-only accounts](flows/password-reset.md) |

¹ Authenticated implicitly via the refresh token in the request body, not a Bearer header.

## MFA (`/mfa` prefix)

| Method | Path | Auth required | Description |
|---|---|---|---|
| POST | `/mfa/setup` | Yes | [MFA](mfa.md) |
| POST | `/mfa/confirm` | Yes | [MFA](mfa.md) |
| POST | `/mfa/disable` | Yes | [MFA](mfa.md) |

## OAuth (`/oauth` prefix)

| Method | Path | Auth required | Description |
|---|---|---|---|
| GET | `/oauth/accounts` | Yes | [Account linking](oauth/account-linking.md) |
| GET | `/oauth/{provider}/authorize` | Optional² | [OAuth overview](oauth/overview.md) |
| POST | `/oauth/{provider}/callback` | No | [OAuth overview](oauth/overview.md) |
| POST | `/oauth/{provider}/connect` | Yes | [OAuth overview](oauth/overview.md) |
| DELETE | `/oauth/{provider}/disconnect` | Yes | [OAuth overview](oauth/overview.md) |

² A valid Bearer token changes this endpoint's behavior from "login" to "connect" mode — see [OAuth overview](oauth/overview.md#1-get-the-authorization-url).

## Authentication header

Every authenticated endpoint expects:

```
Authorization: Bearer <access_token>
```

## Exception → status code reference

Every flow raises a typed `AuthError` subclass; the router converts it to the matching `HTTPException` automatically.

| Exception | Status | | Exception | Status |
|---|---|---|---|---|
| `EmailAlreadyExists` | 409 | | `InvalidToken` | 400 |
| `UsernameAlreadyExists` | 409 | | `TokenExpired` | 400 |
| `PhoneAlreadyExists` | 409 | | `TokenRevoked` | 401 |
| `WeakPassword` | 422 | | `TokenAlreadyUsed` | 400 |
| `InvalidEmail` | 422 | | `SamePassword` | 422 |
| `AlreadyVerified` | 409 | | `PasswordNotSet` | 400 |
| `RateLimited` | 429 | | `PasswordAlreadySet` | 400 |
| `InvalidCredentials` | 401 | | `UserNotFound` | 404 |
| `AccountInactive` | 403 | | `ForbiddenError` | 403 |
| `AccountLocked` | 423 | | `MFANotEnabled` | 400 |
| `EmailNotVerified` | 403 | | `MFAAlreadyEnabled` | 409 |
| `InvalidMFACode` | 401 | | `InvalidBackupCode` | 401 |
| `MFARequired` | 403 | | `OAuthProviderNotConfigured` | 404 |
| `OAuthStateMismatch` | 400 | | `EmailAlreadyRegistered` | 409 |
| `OAuthCodeExchangeFailed` | 502 | | `ProviderAlreadyLinked` | 409 |
| `OAuthUserInfoFailed` | 502 | | `LastLoginMethod` | 400 |
| `OAuthAccountNotFound` | 404 | | | |

Every response body follows FastAPI's standard error shape:

```json
{ "detail": "human-readable message" }
```
