<div align="center">

# authwarden

**A production-grade, pluggable authentication library for FastAPI.**

[![PyPI version](https://img.shields.io/pypi/v/authwarden.svg)](https://pypi.org/project/authwarden/)
[![Python versions](https://img.shields.io/pypi/pyversions/authwarden.svg)](https://pypi.org/project/authwarden/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/timihack/authwarden/blob/main/LICENSE)
[![Tests](https://img.shields.io/badge/tests-521%20passing-brightgreen.svg)](https://github.com/timihack/authwarden)

JWT auth, OAuth2 across 8 providers, MFA, RBAC, and full flow flexibility — all behind a clean FastAPI router you can drop into any app.

[Quickstart](#quickstart) · [Features](#features) · [Documentation](https://timihack.github.io/authwarden) · [Roadmap](https://github.com/timihack/authwarden/discussions)

</div>

---

## Why authwarden

Most FastAPI auth tutorials show you a toy JWT example and stop there. authwarden is built for the parts that actually matter in production:

- **Everything is a `Protocol`.** A SQLAlchemy store ships in the box (`authwarden[sqlalchemy]`). For anything else, the `AbstractUserStore` protocol works with MongoDB/Beanie, SQLModel, or Tortoise through a thin adapter you write. Same for your email/SMS provider and templates.
- **Flexibility where it counts.** Verify by link or OTP. Notify by email, SMS, or both. Let users log in with email, username, or phone — your call, configured once.
- **Security defaults that are actually defaults.** Brute-force lockout, OTP attempt limiting, encrypted OAuth tokens at rest, PKCE on every social login flow — none of it bolted on, none of it optional homework.
- **A real test suite.** 521 tests across unit, flow, and full HTTP end-to-end coverage.

---

## How it compares

authwarden is a complete auth layer: routes, flows, and a storage protocol. [Authlib](https://authlib.org) is a lower-level OAuth/OIDC toolkit, and authwarden uses it internally for the OAuth client. The closest alternative is [fastapi-users](https://github.com/fastapi-users/fastapi-users).

| | authwarden | fastapi-users |
|---|---|---|
| Project status | Active | Maintenance mode: security and dependency updates only |
| Register, login, password reset, email verification | ✅ | ✅ |
| Social login | 8 providers including Apple, PKCE on all | ✅ |
| MFA (TOTP + backup codes) | ✅ | Not in its feature list |
| Role hierarchy and scopes | ✅ | Not in its feature list |
| Login lockout and OTP attempt limits | ✅ | Not in its feature list |
| Cookie transport | Not yet | ✅ |
| Token strategies | JWT, Redis | JWT, database, Redis |
| Built-in ORM stores | SQLAlchemy (more planned) | ✅ |

Compared against the fastapi-users README as of October 2026. Check its current docs before deciding.

---

## Features

**Authentication**
- Register, login, logout, refresh (with rotation)
- Email verification — link or OTP, your choice
- Password reset — link or OTP, your choice
- Change password, and `set-password` for OAuth-only accounts
- Login via email, username, or phone — configurable priority order
- Email *and* SMS notification channels, independently configurable

**MFA**
- TOTP setup, confirm, disable
- 8 single-use, argon2-hashed backup codes per user

**Permissions**
- Role hierarchy (`guest` → `user` → `moderator` → `admin` → `superadmin`)
- Arbitrary scope strings (`"user:read"`, `"admin:delete"`, anything you want)

**OAuth 2.0 / Social Login**
- Google, GitHub, Facebook, Microsoft, LinkedIn, Discord, Twitter/X, Apple
- PKCE (S256) on every provider, no exceptions
- Automatic account linking (existing link → verified-email match → auto-register)
- Apple's quirks handled for you: ES256 client-secret generation, JWKS-cached `id_token` verification, first-login-only name capture
- OAuth tokens encrypted at rest

**Security**
- Login lockout after configurable failed attempts
- OTP attempt limiting with auto-invalidation
- Anti-enumeration on password reset and resend-verification
- Single-use, hashed reset/verification tokens — raw tokens never touch storage

---

## Installation

```bash
pip install authwarden
```

Optional extras:

```bash
pip install "authwarden[redis]"   # Redis sessions, token blacklist, and token strategy
pip install "authwarden[sns]"     # AWS SNS SMS backend
pip install "authwarden[sqlalchemy]"  # built-in SQLAlchemy user store
pip install "authwarden[all]"     # everything
```

---

## Quickstart

```python
from fastapi import FastAPI, Depends
from authwarden import AuthWarden, WardenConfig, MemoryUserStore

config = WardenConfig(
    secret_key="change-me-to-a-real-32-byte-secret",
    require_email_verification=False,  # skip for this example
)
store = MemoryUserStore()  # swap for your own AbstractUserStore in production
warden = AuthWarden(config=config, user_store=store)

app = FastAPI()
app.include_router(warden.router, prefix="/auth", tags=["auth"])


@app.get("/profile")
async def profile(user=Depends(warden.current_user)):
    return {"id": user.id, "email": user.email}


@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, _=Depends(warden.require_roles("admin"))):
    ...
```

Run it:

```bash
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs` — you now have working `/auth/register`, `/auth/login`, `/auth/refresh`, MFA, and OAuth endpoints, plus an interactive **Authorize** button for testing protected routes.

---

## Core concepts

### `WardenConfig`
Every behavioral switch lives here — verification method (link/OTP), notification channels, login identifier order, lockout thresholds, OAuth provider credentials, and more. See the [full configuration reference](https://timihack.github.io/authwarden) for every field.

### `AbstractUserStore`
A `Protocol`, not a base class — any object with the right async methods satisfies it. A SQLAlchemy store is built in:

```python
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from authwarden.storage.sqlalchemy import SQLAlchemyUserStore, create_tables

engine = create_async_engine("postgresql+asyncpg://user:password@localhost/app")
store = SQLAlchemyUserStore(async_sessionmaker(engine, expire_on_commit=False))
warden = AuthWarden(config=config, user_store=store)
# once at startup: await create_tables(engine)
```

For MongoDB/Beanie, SQLModel, Tortoise or anything else, implement the protocol yourself. Examples are in the [full docs](https://timihack.github.io/authwarden).

### Extending the user model
`UserInDB` supports arbitrary extra data without a migration, or full subclassing for typed fields:

```python
class MyUser(UserInDB):
    company_id: str | None = None
    subscription_tier: str = "free"
```

### The `AuthWarden` facade
- `warden.router` — mount it, get 20 endpoints
- `warden.current_user` — `Depends()`-compatible, fetches fresh from your store, checks `is_active` on every request
- `warden.require_roles(*roles)` / `warden.require_scopes(*scopes)` — guard any route you write yourself

---

## Testing

```bash
git clone https://github.com/timihack/authwarden
cd authwarden
pip install -e ".[dev]"
pytest
```

390 tests across foundation, auth flows, MFA/permissions, OAuth, router assembly, and full HTTP end-to-end coverage.

---

## Documentation

This README gets you to a working quickstart. For the complete reference — every config field, every flow with code samples, every customization pattern — see the [full documentation site](https://timihack.github.io/authwarden).

## Roadmap

Tracked in the [project discussion](https://github.com/timihack/authwarden/discussions) — includes planned post-v1.0 work like transport/strategy pluggability, Enterprise OIDC, SAML 2.0, and built-in ORM backend implementations.

## Contributing

Issues and PRs welcome. This project is in active development — check the roadmap discussion before starting major work.

## License

MIT © [timihack](https://github.com/timihack)