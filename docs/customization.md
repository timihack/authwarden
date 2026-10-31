# Customization Guide

A quick reference pulling together every extension point covered in detail elsewhere on this site.

## Which endpoints are mounted

Mount a subset of the router by group or endpoint name. See [`build_router`](concepts/facade.md).

```python
app.include_router(warden.build_router(exclude={"oauth", "mfa"}), prefix="/auth")
```

## Database

Implement [`AbstractUserStore`](concepts/user-store.md) — full examples for SQLAlchemy, MongoDB/Beanie, SQLModel, and Tortoise.

```python
warden = AuthWarden(config=config, user_store=YourUserStore())
```

## User model fields

Extend [`UserInDB`](concepts/user-model.md) via `extra_data` (no subclass needed) or full subclassing with typed fields.

## Email delivery

Swap or write your own [email backend](notifications/email.md) — built-ins exist for console, SMTP, SendGrid, Mailgun.

```python
warden = AuthWarden(config=config, user_store=store, email_backend=YourBackend())
```

## SMS delivery

Same pattern, [SMS backends](notifications/sms.md) — console, Twilio, AWS SNS built in.

```python
warden = AuthWarden(config=config, user_store=store, sms_backend=YourBackend())
```

## Email/SMS copy

Override [`EmailTemplates`](notifications/email.md#overriding-email-copy) / [`SmsTemplates`](notifications/sms.md#overriding-sms-copy) — subclass and override only the methods you want to change.

```python
warden = AuthWarden(config=config, user_store=store, email_templates=MyTemplates())
```

## Full notification routing logic

If templates and backends aren't enough — say, you want push notifications instead of email/SMS entirely — implement `AbstractNotificationService` from scratch:

```python
class MyNotificationService:
    async def send_verification_link(self, user, link): ...
    async def send_verification_otp(self, user, otp): ...
    async def send_welcome(self, user): ...
    async def send_password_reset_link(self, user, link): ...
    async def send_password_reset_otp(self, user, otp): ...
    async def send_password_changed(self, user): ...
    async def send_mfa_enabled(self, user): ...
    async def send_mfa_disabled(self, user): ...

warden = AuthWarden(config=config, user_store=store, notification_service=MyNotificationService())
```

## Password hashing

```python
from authwarden.authentication.password import PasswordHandler

warden = AuthWarden(config=config, user_store=store, password_handler=PasswordHandler(config))
```

Mostly useful if you want to construct it with non-default settings before passing it in — the hasher algorithm itself is chosen via `WardenConfig.password_hasher`.

## Token strategy

Tokens are JWTs by default. Switch to opaque, server-side tokens with instant revocation by passing a [Redis token strategy](concepts/token-strategies.md):

```python
warden = AuthWarden(config=config, user_store=store, token_strategy=RedisTokenStrategy.from_url(config, "redis://localhost:6379/0"))
```

## Token blacklist (multi-process deployments)

`MemoryTokenBlacklist` (the default) only works within a single process. For anything horizontally scaled, use Redis:

```python
import redis.asyncio as redis

from authwarden.authentication.jwt import RedisTokenBlacklist

client = redis.from_url("redis://localhost:6379/0")
warden = AuthWarden(config=config, user_store=store, token_blacklist=RedisTokenBlacklist(client))
```

## OAuth state storage (multi-process deployments)

Same concern as the token blacklist — `MemoryOAuthStateStore` doesn't share state across processes. Implement `AbstractOAuthStateStore` against Redis or your database if you're running more than one process.

```python
warden = AuthWarden(config=config, user_store=store, oauth_state_store=YourStateStore())
```

## Sessions

`session_backend` is independent of JWT auth — JWTs work with no session backend configured at all. Only set this if you want `SessionData` records created on login (device/IP fingerprinting, "log out all devices" style features).

```python
config = WardenConfig(secret_key="...", session_backend="redis", redis_url="redis://...")
```

## What's deliberately *not* customizable today

A few things are fixed by design rather than configurable — noted here so you're not searching for an option that doesn't exist:

- **Transport** — tokens are always returned in the JSON response body; there's no built-in cookie transport. See the [project roadmap](https://github.com/timihack/authwarden/discussions) — this is planned post-1.0.
- **Database-backed tokens** — the token strategies are JWT and Redis. A database-backed strategy isn't built in. You can write your own with the [three-method interface](concepts/token-strategies.md#writing-your-own-strategy).
- **SAML / Enterprise OIDC** — only consumer OAuth (fixed named providers) is supported currently; per-tenant identity provider configs are on the roadmap.