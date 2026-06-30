# User Model

## `UserInDB`

The full storage model. Never returned from the API directly — always projected through `UserRead` via `.to_read()`.

```python
class UserInDB(UserBase):
    model_config = ConfigDict(from_attributes=True, extra="allow")

    id: str
    hashed_password: str | None = None       # None for OAuth-only accounts

    phone_number: str | None = None
    phone_verified: bool = False

    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = []
    scopes: list[str] = []
    extra_data: dict[str, Any] = {}

    mfa_enabled: bool = False
    mfa_secret: str | None = None
    backup_codes: list[str] = []             # argon2 hashes, never plaintext

    failed_login_attempts: int = 0
    locked_until: datetime | None = None
    # ... and the verification/reset OTP + token-hash fields
```

(`UserBase` provides `email`, `username`, `full_name`.)

## Extending it

### Option 1 — `extra_data`, for simple cases

No subclassing needed. `extra="allow"` means any extra kwarg gets stored automatically:

```python
user = UserInDB(email="a@example.com", extra_data={"company_id": "acme-1", "plan": "pro"})
```

### Option 2 — full subclassing, for typed fields

```python
class MyUser(UserInDB):
    company_id: str | None = None
    subscription_tier: str = "free"
    onboarding_complete: bool = False
```

Your `AbstractUserStore` implementation just returns `MyUser` instances instead of `UserInDB` — nothing else in authwarden needs to know about the subclass, since every internal usage only touches the base fields.

### Projecting custom fields to the API response

`to_read()` only returns base `UserRead` fields by default. Override it if you want custom fields to actually reach the API response:

```python
class MyUserRead(UserRead):
    company_id: str | None = None
    subscription_tier: str = "free"

class MyUser(UserInDB):
    company_id: str | None = None
    subscription_tier: str = "free"

    def to_read(self) -> MyUserRead:
        base = super().to_read().model_dump()
        return MyUserRead(**base, company_id=self.company_id, subscription_tier=self.subscription_tier)
```

## `UserCreate`

The `/auth/register` request body:

```python
class UserCreate(UserBase):
    password: str
    phone_number: str | None = None
```

## `UserRead`

The public-safe projection returned by every endpoint — never includes `hashed_password`, MFA secrets, backup codes, or internal reset/verification state.

```python
class UserRead(UserBase):
    id: str
    is_active: bool
    is_verified: bool
    is_superuser: bool
    roles: list[str]
    scopes: list[str]
    mfa_enabled: bool
    created_at: datetime
    updated_at: datetime
```
