# Security

What's protected by default, and why — not an exhaustive threat model, but the reasoning behind the choices that aren't obvious from the code alone.

## Password storage

Argon2 by default (`pwdlib`), bcrypt available as an alternative via `password_hasher`. Hashes are automatically upgraded in place — `verify_and_update()` runs on every login, and if the stored hash uses outdated parameters, it's silently rehashed with current settings before the next request, with zero action needed from your application.

## Timing attacks

`login_flow` runs a dummy password verification even when the identifier doesn't exist, so "wrong password" and "no such account" take statistically the same amount of time to respond. Without this, an attacker could use response latency alone to enumerate valid accounts.

## Anti-enumeration

`forgot_password` and `resend_verification` always return `200`, regardless of whether the identifier exists or is already in the requested state. The only way either ever surfaces an error is `RateLimited` — which itself reveals nothing about whether the account exists, since the same rate limit window applies whether or not the lookup succeeds.

## Token storage

Verification links and password reset links are signed (`itsdangerous`) but the **raw token is never stored** — only a SHA-256 hash, compared via constant-time comparison (`hmac.compare_digest`) on verification. Even a full database read can't recover a usable token.

## Single-use enforcement

Password reset tokens (link mode) track `reset_token_used_at` — a second attempt with the same token, even before expiry, fails with `TokenAlreadyUsed`.

## Brute force protection

Login lockout (`max_login_attempts`/`login_lockout_duration`) and OTP attempt limiting (`max_otp_attempts`) are both on by default, not opt-in. OTP invalidation on hitting the limit happens **within the same request that crosses the threshold** — not on the next call after — closing a timing gap that's easy to get wrong.

## OAuth state — CSRF protection

PKCE state is single-use (`get_and_delete` removes it on read) and encodes its own purpose (`login` vs `connect`) and, for `connect`, the specific user it belongs to. A state minted for one purpose or user can't be replayed against another — this is what actually prevents OAuth CSRF, not just the `state` parameter's mere presence.

## OAuth tokens at rest

Access and refresh tokens returned by social providers are encrypted (Fernet) before storage, using a key derived from `secret_key` via SHA-256. They're never returned in any API response — `OAuthAccountRead` only exposes `id`, `provider`, `email`, `created_at`.

## CSRF (general)

authwarden's router returns tokens in the JSON response body, not as cookies — Bearer-token auth via the `Authorization` header isn't vulnerable to traditional CSRF, since browsers don't auto-attach custom headers cross-origin the way they do cookies. If you build your own layer on top that stores the access token in a cookie instead, you'll need your own CSRF protection (double-submit cookie or `SameSite=Strict`) — that's outside what the default router does.

## What's *not* handled for you

- **Rate limiting at the infrastructure level** — the rate limits described above are per-account, not per-IP. A reverse proxy or API gateway rate limit is still worth adding in front of any public auth endpoint.
- **Secret management** — `secret_key` should be a real random value of at least 32 bytes, sourced from your secrets manager, not a code constant.
- **TLS** — assumed to be terminated somewhere in front of your app; authwarden doesn't enforce HTTPS itself.
