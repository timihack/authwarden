# The AuthWarden Facade

`AuthWarden` is the single object that wires together everything else — password hashing, JWT, sessions, notifications, OAuth providers — behind one constructor.

```python
from authwarden import AuthWarden, WardenConfig

warden = AuthWarden(
    config=WardenConfig(secret_key="..."),
    user_store=MyUserStore(),
)
```

## Constructor

```python
AuthWarden(
    config: WardenConfig,
    user_store: AbstractUserStore,
    *,
    email_backend: AbstractEmailBackend | None = None,
    sms_backend: AbstractSmsBackend | None = None,
    notification_service: AbstractNotificationService | None = None,
    email_templates: EmailTemplates | None = None,
    sms_templates: SmsTemplates | None = None,
    password_handler: PasswordHandler | None = None,
    token_blacklist: AbstractTokenBlacklist | None = None,
    session_backend: AbstractSessionBackend | None = None,
    oauth_state_store: AbstractOAuthStateStore | None = None,
)
```

Every keyword-only argument is an override — if you don't pass it, a sensible default gets built from `config`. The two required positional arguments are `config` and `user_store`.

### Why pass backends directly instead of through config?

`email_backend` and `sms_backend` exist because `WardenConfig.email_backend` only auto-selects between `"console"` and `"smtp"` — SendGrid, Mailgun, Twilio, and AWS SNS don't have a clean single-field config representation, so you build and pass the instance yourself:

```python
from authwarden.email.sendgrid import SendGridEmailBackend

warden = AuthWarden(
    config=config,
    user_store=store,
    email_backend=SendGridEmailBackend(api_key="...", from_address="noreply@yourapp.com"),
)
```

## What it exposes

### `warden.router`

A `fastapi.APIRouter` combining all 20 endpoints (auth, MFA, OAuth). Mount it like any router:

```python
app.include_router(warden.router, prefix="/auth", tags=["auth"])
```

### `warden.current_user`

A `Depends()`-compatible dependency resolving the authenticated user. Two things happen on every call: the JWT is decoded and verified (checked against the token blacklist), then the user is fetched fresh from your store and checked for `is_active`.

```python
@app.get("/profile")
async def profile(user: UserInDB = Depends(warden.current_user)):
    return {"id": user.id, "email": user.email}
```

This means a deactivated user's still-unexpired token stops working immediately — not just at next expiry.

### `warden.require_roles(*roles, require_all=False)`

Returns a `Depends()`-compatible dependency checking the JWT's embedded roles (no extra database call).

```python
@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, _=Depends(warden.require_roles("admin"))):
    ...

# Require ALL listed roles, not just any one
@app.post("/sensitive")
async def sensitive(_=Depends(warden.require_roles("admin", "verified", require_all=True))):
    ...
```

See [Permissions](../permissions.md) for the full role hierarchy.

### `warden.require_scopes(*scopes, require_all=False)`

Same pattern, for scope strings instead of roles:

```python
@app.post("/posts")
async def create_post(_=Depends(warden.require_scopes("posts:write"))):
    ...
```

## Direct access to internals

Everything `AuthWarden` builds is a public attribute, in case you need to use a piece of it directly:

```python
warden.store               # your AbstractUserStore
warden.password_handler    # PasswordHandler
warden.jwt_handler         # JWTHandler
warden.notification_service
warden.session_backend     # None unless config.session_backend is set
warden.oauth_providers     # dict[str, OAuthProviderBase]
warden.oauth_state_store
```
