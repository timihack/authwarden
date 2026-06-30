# Apple Sign In

Apple deviates from standard OAuth2 in three significant ways, all handled internally by `AppleOAuthProvider` — you don't need to work around any of this yourself, but it's worth understanding what's happening.

## 1. The client secret is a signed JWT, regenerated every time

Apple doesn't accept a static client secret string. Instead, you provide a `.p8` private key, and authwarden generates a fresh ES256-signed JWT on every single token exchange, valid for 5 minutes:

```python
config = WardenConfig(
    secret_key="...",
    apple_team_id="YOUR_TEAM_ID",
    apple_key_id="YOUR_KEY_ID",
    apple_private_key_pem="""-----BEGIN PRIVATE KEY-----
...your .p8 file contents...
-----END PRIVATE KEY-----""",
    oauth_providers={
        "apple": OAuthProviderConfig(
            client_id="com.yourapp.service",  # your Services ID, not a typical client_id
            client_secret="",                  # ignored — the real secret is generated per-request
            redirect_uri="https://yourapp.com/auth/callback/apple",
        ),
    },
)
```

The `client_secret` field on `OAuthProviderConfig` is effectively unused for Apple — it's there because the config shape is shared across all providers, but the real secret is generated fresh from `apple_team_id`/`apple_key_id`/`apple_private_key_pem` on every exchange.

## 2. Name is only ever sent once, on the user's first authorization

Every other provider's userinfo endpoint returns the same data on every login. Apple only includes the user's name in the **initial POST body** (`form_post` response mode) the very first time they authorize your app — never again on subsequent logins, even for the same user.

If you need the name, your frontend must capture the raw POST body on first login and pass it through:

```json
POST /auth/oauth/apple/callback
{
  "code": "...",
  "state": "...",
  "post_body": { "user": { "name": { "firstName": "...", "lastName": "..." } } }
}
```

`post_body` is optional and ignored by every other provider — it only matters for Apple, and only on a user's first-ever authorization. On repeat logins, `full_name` in the resulting `OAuthUserInfo` will simply be `None` — this is expected, not a bug.

## 3. `id_token` verification, with cached JWKS

Apple has no userinfo REST endpoint — everything comes from the signed `id_token`. authwarden verifies it via `PyJWKClient`, which caches Apple's public keys for 1 hour (`lifespan=3600`) rather than fetching them on every single login. This cache is shared across all `AppleOAuthProvider` instances in the process.

## Private Relay emails

Apple's "Hide My Email" feature gives you an email like `xyz123@privaterelay.appleid.com` instead of the user's real address. authwarden treats this exactly like any other email — it's stored as-is on `OAuthAccount.email` and used for account-linking lookups the same way a real email would be. Mail sent to it (verification, notifications) still reaches the user, forwarded by Apple.
