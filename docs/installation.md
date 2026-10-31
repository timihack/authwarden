# Installation

```bash
pip install authwarden
```

Requires Python 3.10 or later.

## Optional extras

Some backends have additional dependencies that aren't installed by default, to keep the base install light.

| Extra | Installs | Needed for |
|---|---|---|
| `redis` | `redis` | `RedisSessionBackend`, `RedisTokenBlacklist`, `RedisTokenStrategy` |
| `sns` | `boto3` | `AWSSNSSmsBackend` |
| `sqlalchemy` | `sqlalchemy[asyncio]` | `SQLAlchemyUserStore` (you also install a database driver such as `asyncpg` or `aiosqlite`) |
| `all` | both of the above | everything |

```bash
pip install "authwarden[redis]"
pip install "authwarden[sns]"
pip install "authwarden[sqlalchemy]"
pip install "authwarden[all]"
```

## What's installed by default

These come with the base install — no extra needed:

- **FastAPI** — the router/facade layer
- **Pydantic v2** + **pydantic-settings** — every model and `WardenConfig`
- **pwdlib** (argon2 + bcrypt) — password hashing
- **PyJWT** — JWT issuance and verification
- **itsdangerous** — signed link tokens (email verification, password reset)
- **pyotp** — TOTP for MFA
- **Authlib** + **httpx** — OAuth 2.0 flows
- **cryptography** — Fernet encryption for OAuth tokens at rest, ES256 signing for Apple Sign In
- **aiosmtplib** — the built-in SMTP email backend
- **python-multipart** — required by FastAPI for form-style request parsing

## Verifying the install

```python
import authwarden
print(authwarden.__version__)

from authwarden import AuthWarden, WardenConfig, MemoryUserStore
```

If this runs without error, you're set — head to the [Quickstart](quickstart.md).

## Development install

If you're contributing to authwarden itself:

```bash
git clone https://github.com/timihack/authwarden
cd authwarden
pip install -e ".[dev]"
pytest
```

`[dev]` adds `pytest`, `pytest-asyncio`, and `respx` (for mocking OAuth provider HTTP calls in tests), plus `boto3`, `redis`, `sqlalchemy`, `aiosqlite` and `asyncpg` so the full test suite can run without extra setup.