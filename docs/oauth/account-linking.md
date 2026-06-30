# Account Linking

When a social login callback completes, authwarden resolves which local user it belongs to using this exact order:

## Case 1 — Provider account already linked

```
OAuthAccount(provider="google", provider_user_id="1234") already exists
→ log in as that account's user_id
→ is_new_user = false
```

This is the common case for any returning user.

## Case 2 — Email matches an existing local account

```
No existing OAuthAccount for this (provider, provider_user_id)
The provider's email matches an existing UserInDB.email
```

What happens here depends on `WardenConfig.auto_link_by_email`:

- **`True`** (default): the provider gets linked to that existing account automatically. A user who registered with a password can later "Sign in with Google" using the same email and it just works — no extra step.
- **`False`**: raises `EmailAlreadyRegistered` (409) instead. The user must log in with their password first, then explicitly call `/auth/oauth/{provider}/connect` to link it. Choose this if you want users to consciously opt into linking rather than have it happen silently.

## Case 3 — No match at all, provider gave an email

A brand-new user. An account is created with `is_active=True, is_verified=True` (OAuth providers already verify email ownership, so there's no separate verification step), `hashed_password=None` (OAuth-only — see [`set-password`](../flows/password-reset.md#set-password-oauth-only-accounts) if they later want to add a password), and a welcome notification is sent.

## Case 4 — No match, provider gave no email

Twitter/X doesn't expose email through the standard OAuth2 scopes — `OAuthUserInfo.email` is `None` for that provider. Since `UserInDB.email` is a required field, a synthetic placeholder is generated:

```
twitter_<provider_user_id>@oauth.authwarden.placeholder
```

This satisfies the model's validation without claiming a real email exists. The **stored `OAuthAccount.email` stays `None`** — it's a truthful record that the provider gave no email, even though the user's `UserInDB.email` has a placeholder. If you're building your own UI, check `OAuthAccount.email is None` rather than inspecting the user's placeholder address.

```python
account = await store.get_oauth_account("twitter", provider_user_id)
if account.email is None:
    # this user has no real email on file — don't try to send them anything
    ...
```

## Provider user ID is the source of truth

Across all four cases, `(provider, provider_user_id)` — never email alone — is what identifies *this specific* social login. Email is only used as a secondary signal for linking to an existing account in Case 2. This avoids account-takeover scenarios where someone changes their email at the provider and unexpectedly gets linked to a different local account.
