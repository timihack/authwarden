# Security Policy

authwarden is an authentication library — security issues here have outsized
impact on anyone using it. If you find a vulnerability, please report it
responsibly rather than opening a public issue.

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, use GitHub's private vulnerability reporting:

1. Go to the [Security tab](https://github.com/timihack/authwarden/security) of this repository
2. Click **Report a vulnerability**
3. Provide as much detail as you can: affected version, reproduction steps,
   and impact

This creates a private advisory visible only to maintainers until a fix is
ready, avoiding public disclosure of an exploitable issue before a patch
exists.

## What to Expect

- Acknowledgement of your report as soon as possible
- An assessment of severity and a plan for a fix
- Credit in the eventual security advisory and changelog, unless you
  prefer to remain anonymous

## Scope

In scope:
- Authentication bypass, privilege escalation, token forgery or replay
- OAuth flow vulnerabilities (state/PKCE handling, account-linking abuse)
- Cryptographic weaknesses in password hashing, JWT signing, or token encryption
- Injection or enumeration vulnerabilities in any flow

Out of scope:
- Vulnerabilities in how a consuming application *uses* authwarden
  (e.g. a misconfigured `secret_key`, a custom `AbstractUserStore`
  implementation with its own bugs)
- Vulnerabilities in third-party dependencies — please report those
  upstream, though we're glad to hear about them too

## Supported Versions

As a pre-1.0 project, only the latest published version on PyPI is
supported with security fixes. This will be revisited once a 1.0 release
establishes a more formal support window.