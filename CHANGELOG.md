# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

[Unreleased]: https://github.com/timihack/authwarden/compare/v0.7.1...HEAD
[0.7.1]: https://github.com/timihack/authwarden/compare/v0.7.0...v0.7.1
[0.7.0]: https://github.com/timihack/authwarden/releases/tag/v0.7.0