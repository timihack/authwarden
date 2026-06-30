# Quickstart

## Minimal app

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
```

```bash
uvicorn main:app --reload
```

Open `http://127.0.0.1:8000/docs`. You now have 20 working endpoints under `/auth`, plus an **Authorize** button in Swagger UI for testing protected routes with a Bearer token.

## Try it end-to-end

```bash
# Register
curl -X POST http://127.0.0.1:8000/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email": "you@example.com", "password": "strongpassword123"}'

# Login
curl -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"identifier": "you@example.com", "password": "strongpassword123"}'
# → returns access_token, refresh_token, and user

# Use the access_token on a protected route
curl http://127.0.0.1:8000/profile \
  -H "Authorization: Bearer <access_token>"
```

## Adding a real database

`MemoryUserStore` is for development and testing only — it forgets everything on restart. Swap in your own store by implementing [`AbstractUserStore`](concepts/user-store.md):

```python
warden = AuthWarden(config=config, user_store=MySQLAlchemyUserStore(session_factory))
```

See [Core Concepts → User Store](concepts/user-store.md) for full adapter examples.

## Protecting your own routes

```python
from fastapi import Depends

@app.get("/admin/dashboard")
async def dashboard(_=Depends(warden.require_roles("admin"))):
    ...

@app.post("/posts")
async def create_post(_=Depends(warden.require_scopes("posts:write"))):
    ...
```

See [Permissions](permissions.md) for the full role/scope model.

## Turning on more flexibility

Everything below is one config change away — see the [full Configuration Reference](configuration.md):

```python
config = WardenConfig(
    secret_key="...",
    verification_method="otp",                       # OTP instead of email link
    verification_channels=["email", "sms"],           # send to both
    login_identifier_fields=["email", "username", "phone"],
    enable_mfa=True,
    oauth_providers={
        "google": OAuthProviderConfig(
            client_id="...", client_secret="...", redirect_uri="https://yourapp.com/cb/google"
        ),
    },
)
```
