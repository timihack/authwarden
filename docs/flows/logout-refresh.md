# Logout & Refresh

## Logout

```http
POST /auth/logout
Authorization: Bearer <access_token>
```
```json
{ "refresh_token": "..." }
```

Request body is optional — pass `refresh_token` to revoke it alongside the access token; omit it to only revoke the access token (the refresh token remains valid until it naturally expires).

Both tokens, once revoked, are checked against the blacklist on every subsequent verification — a logged-out token cannot be used again even if it hasn't technically expired.

Returns `204 No Content`.

## Refresh

```http
POST /auth/refresh
```
```json
{ "refresh_token": "..." }
```

```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer"
}
```

When `WardenConfig.enable_refresh_rotation=True` (the default), the old refresh token is blacklisted as part of this call — it cannot be reused. If a stolen refresh token gets used once by an attacker and once by the real user, whichever request lands second gets `TokenRevoked`, which is a useful signal that something's wrong.

## Errors

| Status | Exception | When |
|---|---|---|
| 400 | `TokenExpired` | |
| 401 | `TokenRevoked` | Token already used (rotation) or explicitly logged out. |
| 400 | `InvalidToken` | Malformed, wrong type, or the underlying user is now inactive/deleted. |
