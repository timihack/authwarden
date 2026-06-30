# Registration

```http
POST /auth/register
```

```json
{
  "email": "user@example.com",
  "password": "strongpassword123",
  "username": "optional_username",
  "phone_number": "+15551234567",
  "full_name": "optional name"
}
```

Only `email` and `password` are required. `username` and `phone_number` are optional, but if supplied, must be unique — `register_flow` checks all three identifiers (email, username, phone) for collisions before creating the account.

## What happens

1. Password is checked against the configured policy (`min_password_length`, etc.)
2. Email, username (if given), and phone (if given) are each checked for uniqueness
3. Password is hashed (argon2 by default)
4. If `require_email_verification=True`: the account is created `is_active=False, is_verified=False`, and a verification link or OTP is sent depending on `verification_method`
5. If `require_email_verification=False`: the account is immediately active and verified, no notification sent

## Response

```json
{
  "id": "uuid",
  "email": "user@example.com",
  "username": "optional_username",
  "full_name": null,
  "is_active": false,
  "is_verified": false,
  "is_superuser": false,
  "roles": [],
  "scopes": [],
  "mfa_enabled": false,
  "created_at": "...",
  "updated_at": "..."
}
```

`201 Created` on success.

## Errors

| Status | Exception | When |
|---|---|---|
| 422 | `WeakPassword` | Password fails the configured policy. Message lists every violation, not just the first. |
| 409 | `EmailAlreadyExists` | |
| 409 | `UsernameAlreadyExists` | Only checked if `username` was supplied. |
| 409 | `PhoneAlreadyExists` | Only checked if `phone_number` was supplied. |
