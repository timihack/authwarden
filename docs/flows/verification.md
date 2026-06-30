# Verification

authwarden supports two verification methods, set via `WardenConfig.verification_method`.

## Link mode (default)

```http
POST /auth/verify-email
```
```json
{ "token": "..." }
```

The token comes from the link sent at registration (`itsdangerous`-signed, embedding the email, expiring after `email_verification_ttl` seconds).

## OTP mode

```http
POST /auth/verify-otp
```
```json
{ "identifier": "user@example.com", "otp": "123456" }
```

`identifier` can be an email or phone number — whichever the user registered with and received the OTP on.

OTP wrong-guesses are tracked. After `max_otp_attempts` wrong guesses, the OTP is invalidated immediately (not on the *next* call after the limit — the invalidation happens within the same request that crosses the threshold) and a new one must be requested.

## Resending

```http
POST /auth/resend-verification
```
```json
{ "identifier": "user@example.com" }
```

Always returns `200` regardless of whether the identifier exists or is already verified — this is intentional anti-enumeration behavior, not a bug. Rate-limited to one request per `resend_verification_cooldown` seconds per account.

## Errors

| Status | Exception | When |
|---|---|---|
| 400 | `InvalidToken` | Bad signature (link mode) or wrong OTP (OTP mode). |
| 400 | `TokenExpired` | Link or OTP TTL elapsed, or OTP attempt limit exceeded. |
| 409 | `AlreadyVerified` | |
| 429 | `RateLimited` | Resend requested too soon. |
