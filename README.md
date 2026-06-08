# authwarden

Production-grade FastAPI authentication and authorization library. Wraps proven cryptographic libraries — never rolls its own.

[![Python](https://img.shields.io/badge/python-3.11+-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/fastapi-0.110+-green.svg)](https://fastapi.tiangolo.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PyPI version](https://img.shields.io/pypi/v/authwarden.svg)](https://pypi.org/project/authwarden/)

---

## Features

- **JWT authentication** — access + refresh tokens, rotation, per-token revocation via `jti`
- **Password hashing** — argon2 (default) or bcrypt via `pwdlib`, auto-rehash on login
- **Full auth flows** — register, verify email, login, logout, forgot/reset/change password
- **MFA** — TOTP setup/confirm/disable (pyotp), hashed backup codes
- **OAuth 2.0 / Social login** — Google, GitHub, Facebook, Apple, Twitter/X, Microsoft, LinkedIn, Discord
- **RBAC** — role hierarchy, scope guards, `Depends()` factories
- **Session management** — pluggable backends (in-memory, Redis)
- **Email** — SMTP + console backends, HTML + plain-text templates for every flow
- **Plug-and-play router** — mount all endpoints with one line
- **Storage-agnostic** — implement `AbstractUserStore` for any ORM or database

---

## Installation

```bash
pip install authwarden
```

With Redis session support:

```bash
pip install authwarden[redis]
```

---

## Quickstart

```python
from fastapi import FastAPI, Depends
from authwarden import AuthWarden, WardenConfig
from authwarden.storage.memory import MemoryUserStore

app = FastAPI()

warden = AuthWarden(
    config=WardenConfig(secret_key="your-secret-key"),
    user_store=MemoryUserStore(),
)

# Mount all auth endpoints under /auth
app.include_router(warden.router, prefix="/auth", tags=["auth"])

# Protect your own routes
@app.get("/profile")
async def profile(user=Depends(warden.current_user)):
    return user

@app.delete("/admin/users/{user_id}")
async def delete_user(user=Depends(warden.require_roles("admin"))):
    ...
```

This mounts:

```
POST /auth/register
POST /auth/verify-email
POST /auth/resend-verification
POST /auth/login
POST /auth/logout
POST /auth/refresh
POST /auth/forgot-password
POST /auth/reset-password
POST /auth/change-password
POST /auth/mfa/setup
POST /auth/mfa/confirm
POST /auth/mfa/disable
GET  /auth/oauth/{provider}/authorize
POST /auth/oauth/{provider}/callback
POST /auth/oauth/{provider}/connect
DEL  /auth/oauth/{provider}/disconnect
GET  /auth/oauth/accounts
POST /auth/set-password
```

---

## Configuration

```python
from authwarden import WardenConfig

config = WardenConfig(
    # Required
    secret_key="a-long-random-secret",

    # JWT
    algorithm="HS256",
    access_token_ttl=900,        # 15 minutes
    refresh_token_ttl=604800,    # 7 days
    enable_refresh_rotation=True,

    # Passwords
    password_hasher="argon2",    # or "bcrypt"
    min_password_length=8,
    require_password_uppercase=False,
    require_password_digit=False,
    require_password_special=False,

    # Email
    email_backend="smtp",        # or "console" for dev
    smtp_host="smtp.example.com",
    smtp_port=587,
    smtp_username="user@example.com",
    smtp_password="...",
    emails_from_address="noreply@example.com",

    # Registration
    require_email_verification=True,
    allow_registration=True,

    # MFA
    enable_mfa=True,
    mfa_issuer_name="MyApp",

    # Session (optional)
    session_backend="redis",
    redis_url="redis://localhost:6379",

    # Frontend URLs (for email links)
    frontend_base_url="https://myapp.com",
    verify_email_path="/auth/verify-email",
    reset_password_path="/auth/reset-password",
)
```

All settings can also be loaded from environment variables (via `pydantic-settings`):

```env
SECRET_KEY=your-secret-key
EMAIL_BACKEND=smtp
SMTP_HOST=smtp.example.com
```

---

## Custom User Store

Implement `AbstractUserStore` to connect any database:

```python
from authwarden.storage.base import AbstractUserStore
from authwarden.models.user import UserInDB

class SQLAlchemyUserStore(AbstractUserStore):
    async def get_by_id(self, user_id: str) -> UserInDB | None:
        ...

    async def get_by_email(self, email: str) -> UserInDB | None:
        ...

    async def create(self, user: UserInDB) -> UserInDB:
        ...

    async def update(self, user: UserInDB) -> UserInDB:
        ...

    async def delete(self, user_id: str) -> None:
        ...
```

---

## OAuth / Social Login

```python
from authwarden.authentication.oauth import OAuthProviderConfig

warden = AuthWarden(
    config=WardenConfig(
        secret_key="...",
        oauth_providers={
            "google": OAuthProviderConfig(
                client_id="...",
                client_secret="...",
                redirect_uri="https://myapp.com/auth/oauth/google/callback",
            ),
            "github": OAuthProviderConfig(
                client_id="...",
                client_secret="...",
                redirect_uri="https://myapp.com/auth/oauth/github/callback",
            ),
        }
    ),
    user_store=MyUserStore(),
)
```

**Apple Sign In** requires additional fields:

```python
config = WardenConfig(
    ...
    apple_team_id="TEAM123",
    apple_key_id="KEY123",
    apple_private_key_pem="-----BEGIN PRIVATE KEY-----\n...",
    oauth_providers={
        "apple": OAuthProviderConfig(
            client_id="com.myapp.service",
            client_secret="",   # auto-generated from private key
            redirect_uri="https://myapp.com/auth/oauth/apple/callback",
        )
    }
)
```

---

## MFA (TOTP)

```python
# Enable globally
config = WardenConfig(secret_key="...", enable_mfa=True)

# Endpoints are automatically mounted:
# POST /auth/mfa/setup    → returns { secret, qr_uri, backup_codes }
# POST /auth/mfa/confirm  → activates MFA after verifying first code
# POST /auth/mfa/disable  → requires password + TOTP or backup code
```

Login with MFA:

```python
POST /auth/login
{
  "email": "user@example.com",
  "password": "hunter2",
  "totp_code": "123456"
}
```

---

## RBAC

```python
from fastapi import Depends

# Require a single role
@app.get("/admin")
async def admin(user=Depends(warden.require_roles("admin"))):
    ...

# Require any of multiple roles
@app.get("/reports")
async def reports(user=Depends(warden.require_roles("admin", "analyst"))):
    ...

# Require a scope
@app.post("/items")
async def create_item(user=Depends(warden.require_scopes("items:write"))):
    ...
```

---

## Email Templates

Override any template by subclassing `EmailTemplates`:

```python
from authwarden.email.templates import EmailTemplates

class MyTemplates(EmailTemplates):
    def verify_email(self, user, link: str) -> tuple[str, str, str]:
        # returns (subject, plain_text, html)
        return (
            "Verify your account",
            f"Click here: {link}",
            f"<a href='{link}'>Verify your account</a>",
        )

warden = AuthWarden(config=..., user_store=..., email_templates=MyTemplates())
```

---

## Auth Flows Reference

| Flow | Endpoint | Auth required |
|---|---|---|
| Register | `POST /auth/register` | No |
| Verify email | `POST /auth/verify-email` | No |
| Resend verification | `POST /auth/resend-verification` | No |
| Login | `POST /auth/login` | No |
| Logout | `POST /auth/logout` | Bearer token |
| Refresh token | `POST /auth/refresh` | No |
| Forgot password | `POST /auth/forgot-password` | No |
| Reset password | `POST /auth/reset-password` | No |
| Change password | `POST /auth/change-password` | Bearer token |
| MFA setup | `POST /auth/mfa/setup` | Bearer token |
| MFA confirm | `POST /auth/mfa/confirm` | Bearer token |
| MFA disable | `POST /auth/mfa/disable` | Bearer token |
| OAuth authorize | `GET /auth/oauth/{provider}/authorize` | No |
| OAuth callback | `POST /auth/oauth/{provider}/callback` | No |
| Connect provider | `POST /auth/oauth/{provider}/connect` | Bearer token |
| Disconnect provider | `DELETE /auth/oauth/{provider}/disconnect` | Bearer token |
| List linked accounts | `GET /auth/oauth/accounts` | Bearer token |
| Set password (OAuth) | `POST /auth/set-password` | Bearer token |

---

## Security Notes

- Passwords hashed with **argon2** by default (bcrypt available)
- JWT tokens include a `jti` (UUID) claim — enables per-token revocation
- Password reset and email verification tokens stored as **hashes only**
- Forgot password and resend verification always return `200` (anti-enumeration)
- Constant-time comparison used for all token lookups (`hmac.compare_digest`)
- PKCE (S256) used for all OAuth flows
- Refresh token rotation enabled by default — old `jti` blacklisted on use
- MFA backup codes stored as **argon2 hashes**, single-use
- OAuth provider tokens encrypted at rest (Fernet)

---

## Development

```bash
git clone https://github.com/yourusername/authwarden.git
cd authwarden
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

---

## Running Tests

```bash
# All tests
pytest

# With coverage
pytest --cov=authwarden --cov-report=term-missing

# Specific suite
pytest tests/test_oauth.py -v
```

---

## Project Structure

```
authwarden/
├── core/              # WardenConfig, AuthWarden facade, request context
├── authentication/    # JWT, password hashing, OAuth provider base
├── flows/             # One module per auth flow
├── mfa/               # TOTP + backup codes
├── permissions/       # Roles + scope guards
├── session/           # Memory + Redis session backends
├── dependencies/      # FastAPI Depends() factories
├── routers/           # Plug-and-play FastAPI routers
├── email/             # SMTP, console backends + templates
├── models/            # Pydantic v2 models
└── storage/           # AbstractUserStore + MemoryUserStore
```

---

## License

MIT — see [LICENSE](LICENSE).