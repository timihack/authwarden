# Permissions (RBAC)

Two independent systems: **roles** (hierarchical) and **scopes** (flat strings). Both are embedded in the JWT at issue time — checking them is a pure in-memory operation, no extra database call.

## Roles

A fixed hierarchy, low to high:

```
guest → user → moderator → admin → superadmin
```

```python
from authwarden.permissions.roles import has_role, has_min_role, require_roles, require_min_role

require_roles(payload, "admin")                              # exactly "admin" present
require_roles(payload, "admin", "moderator")                  # any one of these
require_roles(payload, "admin", "verified", require_all=True) # all required
require_min_role(payload, "moderator")                        # "moderator" or higher in the hierarchy
```

Through the facade, in a route:

```python
@app.delete("/admin/users/{user_id}")
async def delete_user(user_id: str, _=Depends(warden.require_roles("admin"))):
    ...
```

## Scopes

Plain strings — no format enforced. `"user:read"`, `"admin:delete"`, `"posts:write"` are all just strings the library checks for membership in the token's scope list.

```python
from authwarden.permissions.policies import has_scope, require_scopes

require_scopes(payload, "posts:write")
require_scopes(payload, "posts:read", "posts:write")                  # any one
require_scopes(payload, "posts:read", "posts:write", require_all=True) # both
```

```python
@app.post("/posts")
async def create_post(_=Depends(warden.require_scopes("posts:write"))):
    ...
```

## Setting roles and scopes on a user

There's no dedicated endpoint for this — it's a direct field on `UserInDB` (`roles: list[str]`, `scopes: list[str]`), set however your application logic decides (an admin panel, a database migration, a Stripe webhook on subscription purchase, etc.). Whatever's on the user record at the time they log in gets embedded into their JWT.

```python
user.roles = ["admin"]
user.scopes = ["posts:write", "posts:delete"]
await store.update(user)
```

## Why no database re-fetch on every permission check

Roles/scopes come from the JWT payload, not a fresh lookup — this is the standard JWT tradeoff. If you revoke someone's admin role, it takes effect on their *next* token refresh, not instantly. With the default 15-minute access token TTL, that's a small window. If you need instant revocation for some specific action, fetch the user via `warden.current_user` instead and check `user.roles` directly in your route body.

## Errors

| Status | Exception | When |
|---|---|---|
| 403 | `ForbiddenError` | Role or scope check failed. Message lists what was required vs. what the token actually has. |
