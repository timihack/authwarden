# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [1.3.0] - 2026-10-25
### Added
- Token strategies. The new `TokenStrategy` protocol lets you replace JWT as the token mechanism, through `AuthWarden(token_strategy=...)`. `RedisTokenStrategy` is built in: opaque random tokens stored in Redis, with instant revocation. Install with `pip install "authwarden[redis]"`.
- `JWTHandler.issue_token_pair()`, the async form of `create_token_pair()`.
- `warden.token_strategy`. `warden.jwt_handler` still works and is an alias for it.
- CI now runs the suite against a Redis service too.

### Fixed
- Docs: the `RedisTokenBlacklist` example passed `redis_url=`, which the class does not accept. It takes a Redis client.

### Documentation
- Update the SQLModel user-store example for async SQLite sessions, SQLModel 0.0.45+, unique identifiers, and prefixed tables.

## [1.2.0] - 2026-10-24
### Added
- Built-in SQLAlchemy user store: `authwarden.storage.sqlalchemy.SQLAlchemyUserStore`, with `create_tables()` and the `Base` metadata for Alembic. Install with `pip install "authwarden[sqlalchemy]"`. Async SQLAlchemy 2.0+, tested on SQLite and PostgreSQL. Email and username are case-insensitive and unique, and datetimes are timezone-aware on every database.
- CI now runs the test suite against a PostgreSQL service as well as SQLite.

## [1.1.3] - 2026-10-24
### Security
- A wrong TOTP code at login now counts toward the login lockout, like a wrong password. Before, a caller who knew the password could guess the 6-digit code without limit. Upgrade is recommended for anyone using MFA.

### Fixed
- Login now accepts the adjacent 30-second TOTP window, as documented. Before, only the current code worked at login, while MFA setup and disable already accepted the adjacent window.

## [1.1.2] - 2026-10-23
### Security
- Completes the 1.1.1 account-linking fix. Auto-link by email now also requires the local account's email to be verified and `require_email_verification` to be on, because with verification off a local account's email was never proven.
- Accounts created from an OAuth login are marked verified only if the provider verified the email. Before, they were always marked verified, which let an account created from an unverified email be linked into later.
- OAuth login now rejects deactivated accounts (`AccountInactive`, 403). Before, the callback issued tokens without checking `is_active`.
- Existing accounts keep their stored `is_verified` value. Review accounts created through OAuth before this release if your provider could return unverified emails.

## [1.1.1] - 2026-10-23
### Security
- OAuth login no longer links to an existing local account by email unless the provider reports that email as verified. Previously the verification flag was ignored, so an unverified provider email matching a local account could sign in to it. Microsoft and Facebook emails are now always treated as unverified, and GitHub's fallback uses only a verified primary email. Users who relied on auto-link with those two providers get `EmailAlreadyRegistered` and must log in with their password and connect the provider. Upgrade is recommended for everyone using OAuth.

## [1.1.0] - 2026-10-22
### Added
- `AuthWarden.build_router(include=..., exclude=...)` to mount only selected endpoints, by group (`auth`, `mfa`, `oauth`) or endpoint name. `warden.router` is unchanged.

## [1.0.1] - 2026-10-22
### Fixed
- Default email backend was never passed to `NotificationService`. Without an explicit `email_backend=`, all emails (verification, password reset, notifications) were silently dropped, and `email_backend="smtp"` in config had no effect. The backend selected by config is now used.
- Docs: the lockout setting is `max_failed_attempts`, not `max_login_attempts`, and `AccountLocked` returns `403`, not `423`.

## [1.0.0] - 2026-06
First stable release.

### Why 1.0.0 now
`0.7.0`/`0.7.1` proved the package installs and runs correctly in a real
environment outside development. Since then: CI now runs the full suite
on every PR, a security disclosure process is in place, and the README
accurately documents what the library does end-to-end. This release marks
the point where the public API is considered stable — breaking changes
from here follow semver.

### Notes
- No functional changes from `0.7.1` — this release exists to mark API
  stability, not to ship new behavior.
- See the "Phase development history" section below for the full feature
  set this release comprises.

## [0.7.1] - 2026-06
### Fixed
- Added missing `httpx` dependency. `0.7.0`'s published package metadata was
  missing it entirely, causing `import authwarden` to fail immediately for
  every installer. Confirmed and fixed within hours of the `0.7.0` publish.

## [0.7.0] - 2026-06
First publish to PyPI.

### Added
- Full Phase 1–7 feature set in a single package: JWT auth, OAuth2 across
  8 providers, MFA, RBAC, and a FastAPI router/facade tying it all together.
- GitHub Actions pipeline for publishing to PyPI via trusted publishing (OIDC).

### Known issues (fixed in 0.7.1)
- Missing `httpx` dependency broke the import chain entirely. See 0.7.1.

---

## Phase development history

The entries below predate the first PyPI publish and track development
milestones rather than published package versions. Tagged on GitHub as
`v0.1.0-phase1` through `v0.7.0-phase7`.

### Phase 7 — End-to-end HTTP tests
- 67 new tests exercising all 20 endpoints via real HTTP requests
  (`httpx.AsyncClient` + `ASGITransport`), beyond Phase 6's wiring-focused coverage.
- Fixed 4 API drift issues caught by re-running earlier test files against
  reconstructed source: password policy violation aggregation, optional
  JWT blacklist parameter, `SessionData` field naming, JWT decode/blacklist
  method signatures.

### Phase 6 — Assembly
- `AuthWarden` facade wiring every previous phase together.
- FastAPI routers: 20 endpoints across auth, MFA, and OAuth.
- Two-tier dependency injection: lightweight JWT payload decode for
  role/scope checks, full DB-fetch-plus-active-check for `current_user`.
- Fixed: `authwarden/__init__.py` had been silently empty since Phase 2 —
  the documented quickstart did not actually work until this phase.

### Phase 5 — OAuth 2.0 / Social Login
- 8 providers: Google, Facebook, GitHub, Microsoft, LinkedIn, Discord,
  Twitter/X, and Apple (with ES256 client-secret generation and
  JWKS-cached `id_token` verification).
- PKCE (S256) enforced on every provider.
- Account linking: existing link → email match (auto-link or reject) →
  auto-register, with a synthetic placeholder email when a provider
  supplies none (e.g. Twitter).
- OAuth tokens encrypted at rest (Fernet).
- Fixed: Authlib's `AsyncOAuth2Client` silently dropped `code_challenge_method`
  unless passed directly to `create_authorization_url()`.

### Phase 4 — MFA, Permissions, Security hardening
- TOTP MFA: setup, confirm, disable. 8 argon2-hashed, single-use backup codes.
- Role hierarchy and scope-based permission guards.
- Login brute-force lockout (configurable threshold and duration).
- OTP attempt limiting with auto-invalidation.
- Username and phone uniqueness enforcement at registration (previously
  only email was checked).

### Phase 3 — Auth flows
- Register, login, logout, refresh, verify (link or OTP), resend
  verification, forgot/reset password (link or OTP), change password.
- SMS as an alternative/additional notification channel to email.
- Login via email, username, or phone, in configurable priority order.
- `NotificationService` as a single hub routing to email and/or SMS.

### Phase 2 — Auth primitives
- Password hashing (argon2/bcrypt via pwdlib).
- JWT issuance, verification, and revocation via a token blacklist.
- Session backends (in-memory, Redis).

### Phase 1 — Foundation
- Exception hierarchy, Pydantic v2 models, `WardenConfig`,
  `AbstractUserStore` protocol, in-memory reference implementation.

[Unreleased]: https://github.com/timihack/authwarden/compare/v1.3.0...HEAD
[1.3.0]: https://github.com/timihack/authwarden/compare/v1.2.0...v1.3.0
[1.2.0]: https://github.com/timihack/authwarden/compare/v1.1.3...v1.2.0
[1.1.3]: https://github.com/timihack/authwarden/compare/v1.1.2...v1.1.3
[1.1.2]: https://github.com/timihack/authwarden/compare/v1.1.1...v1.1.2
[1.1.1]: https://github.com/timihack/authwarden/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/timihack/authwarden/compare/v1.0.1...v1.1.0
[1.0.1]: https://github.com/timihack/authwarden/compare/v1.0.0...v1.0.1
[1.0.0]: https://github.com/timihack/authwarden/compare/v0.7.1...v1.0.0
[0.7.1]: https://github.com/timihack/authwarden/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/timihack/authwarden/releases/tag/v0.7.0