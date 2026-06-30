# authwarden

**A production-grade, pluggable authentication library for FastAPI.**

JWT auth, OAuth2 across 8 providers, MFA, RBAC, and full flow flexibility — behind a single facade you mount into any FastAPI app.

```bash
pip install authwarden
```

This site is the complete reference. If you just want to get something running in two minutes, start with the [README](https://github.com/timihack/authwarden) instead — come back here when you need a specific config field, flow detail, or customization pattern.

## What's covered here

- **[Installation](installation.md)** and **[Quickstart](quickstart.md)** — same as the README, slightly more detail
- **[Configuration Reference](configuration.md)** — every `WardenConfig` field, what it does, and its default
- **[Core Concepts](concepts/facade.md)** — the `AuthWarden` facade, the `AbstractUserStore` protocol, the `UserInDB` model
- **[Authentication Flows](flows/registration.md)** — every flow, with real request/response examples
- **[MFA](mfa.md)** and **[Permissions](permissions.md)** — TOTP setup and RBAC
- **[OAuth / Social Login](oauth/overview.md)** — all 8 providers, account linking, Apple's special handling
- **[Notifications](notifications/email.md)** — every email/SMS backend and how to write your own
- **[Security](security.md)** — what's protected by default and why
- **[API Reference](api-reference.md)** — every endpoint, every status code
- **[Customization Guide](customization.md)** — subclassing the user model, writing a database adapter, overriding templates

## Design philosophy

authwarden is built around `Protocol`s, not base classes. Almost everything — the user store, the email backend, the SMS backend, the notification service — can be swapped for your own implementation without touching the library's internals. You don't inherit from anything; you just implement the methods the protocol expects.

This means:

- Use any database — the [`AbstractUserStore`](concepts/user-store.md) protocol already works with SQLAlchemy, MongoDB/Beanie, SQLModel, or Tortoise via a thin adapter you write
- Use any email or SMS provider — built-in backends exist for the common ones, but writing your own is a single class with one method
- Extend the user model with your own fields — via `extra_data` or full subclassing, no migration required for the simple case

## Project links

- [GitHub repository](https://github.com/timihack/authwarden)
- [PyPI package](https://pypi.org/project/authwarden/)
- [Issues](https://github.com/timihack/authwarden/issues)
- [Roadmap discussion](https://github.com/timihack/authwarden/discussions)
