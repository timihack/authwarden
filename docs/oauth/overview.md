# OAuth / Social Login — Overview

8 providers, all using the authorization code flow with PKCE (S256) — no exceptions, no provider gets to skip it.

| Provider | Key | Notes |
|---|---|---|
| Google | `google` | OIDC, `id_token` + userinfo endpoint |
| GitHub | `github` | Falls back to `/user/emails` if the primary `/user` response has no public email |
| Facebook | `facebook` | |
| Microsoft | `microsoft` | Azure AD / personal accounts via the common endpoint |
| LinkedIn | `linkedin` | OIDC-compliant `/userinfo` |
| Discord | `discord` | Builds the CDN avatar URL from the response |
| Twitter / X | `twitter` | **No email available** via standard OAuth2 scopes — see [Account Linking](account-linking.md) for how this is handled |
| Apple | `apple` | Significant special-case handling — see [Apple Sign In](apple.md) |

## Configuring a provider

```python
from authwarden import WardenConfig, OAuthProviderConfig

config = WardenConfig(
    secret_key="...",
    oauth_providers={
        "google": OAuthProviderConfig(
            client_id="...",
            client_secret="...",
            redirect_uri="https://yourapp.com/auth/callback/google",
        ),
        "github": OAuthProviderConfig(
            client_id="...",
            client_secret="...",
            redirect_uri="https://yourapp.com/auth/callback/github",
            scopes=["read:user", "user:email"],  # optional — sane defaults apply if omitted
        ),
    },
)
```

## The flow

### 1. Get the authorization URL

```http
GET /auth/oauth/{provider}/authorize
```

```json
{ "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?..." }
```

Redirect the user's browser to this URL.

**This single endpoint serves two purposes**, decided by whether the request carries a valid Bearer token:

- **No Authorization header (or an invalid one):** builds state for the **login** flow — the eventual callback either logs an existing user in or registers a new one
- **Valid Authorization header:** builds state for the **connect** flow — the eventual callback links the provider to *that* authenticated user instead

```python
# Public login flow
GET /auth/oauth/google/authorize

# Connect flow — same endpoint, just authenticated
GET /auth/oauth/google/authorize
Authorization: Bearer <access_token>
```

### 2. Handle the callback

After the user approves access at the provider, your frontend receives a `code` and `state` and posts them to one of two endpoints depending on which flow was started:

**Login** (public):
```http
POST /auth/oauth/{provider}/callback
```
```json
{ "code": "...", "state": "..." }
```
```json
{
  "access_token": "...",
  "refresh_token": "...",
  "token_type": "bearer",
  "user": { "...": "UserRead" },
  "is_new_user": true
}
```

**Connect** (authenticated):
```http
POST /auth/oauth/{provider}/connect
Authorization: Bearer <access_token>
```
```json
{ "code": "...", "state": "..." }
```
```json
{ "id": "...", "provider": "google", "email": "...", "created_at": "..." }
```

The `state` value itself encodes which purpose it was created for — the callback/connect endpoints validate this strictly, so a state minted for login can't be replayed against connect, or vice versa.

### 3. Manage linked accounts

```http
GET /auth/oauth/accounts
Authorization: Bearer <access_token>
```
Returns every linked provider for the current user (no tokens included — just `id`, `provider`, `email`, `created_at`).

```http
DELETE /auth/oauth/{provider}/disconnect
Authorization: Bearer <access_token>
```
`204 No Content` on success. Refuses with `400 LastLoginMethod` if this is the user's *only* way to log in (no password set, no other linked providers) — you can't lock yourself out via this endpoint.

## PKCE state storage

State is single-use — `MemoryOAuthStateStore.get_and_delete()` removes it on read, so it can never be replayed. Default TTL is 10 minutes. For multi-process deployments, pass your own `AbstractOAuthStateStore` implementation (e.g. Redis-backed) to `AuthWarden(oauth_state_store=...)`.

## Token storage

Access and refresh tokens returned by the provider are encrypted at rest (Fernet, key derived from `secret_key`) before being saved to `OAuthAccount.access_token`/`refresh_token`. They're never exposed via any API response.

## Errors

| Status | Exception | When |
|---|---|---|
| 404 | `OAuthProviderNotConfigured` | Unknown provider, or configured with `enabled=False`. |
| 400 | `OAuthStateMismatch` | State doesn't exist, expired, or wrong purpose/user — possible CSRF. |
| 502 | `OAuthCodeExchangeFailed` | The provider rejected the code exchange. |
| 502 | `OAuthUserInfoFailed` | Fetching user info from the provider failed. |
| 409 | `EmailAlreadyRegistered` | Social login's email matches an existing user, and `auto_link_by_email=False`. |
| 409 | `ProviderAlreadyLinked` | Connect called for a provider account already linked to *some* user. |
| 404 | `OAuthAccountNotFound` | Disconnect called for a provider not linked to this user. |
| 400 | `LastLoginMethod` | Disconnect would leave the user with no way to log in. |
