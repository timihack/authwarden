# Token Strategies

A token strategy decides what an access or refresh token is, and how it is verified and revoked. authwarden ships two.

| | JWT (default) | Redis |
|---|---|---|
| Token | Signed JWT, self-contained | Random opaque string. The data lives in Redis |
| Verification | Signature check, then a blacklist lookup | One Redis lookup |
| Revocation | Blacklist entry until the token expires | Immediate. The token is deleted and a revoked marker is kept |
| Needs Redis | No (yes, for revocation across several processes) | Yes |
| Roles and scopes | Embedded at issue time | Stored with the token at issue time |

Both behave the same from your routes. `warden.current_user`, `require_roles` and `require_scopes` work unchanged.

## Using the Redis strategy

```bash
pip install "authwarden[redis]"
```

```python
from authwarden import AuthWarden, WardenConfig
from authwarden.authentication.redis_strategy import RedisTokenStrategy

config = WardenConfig(secret_key="...")
strategy = RedisTokenStrategy.from_url(config, "redis://localhost:6379/0")

warden = AuthWarden(config=config, user_store=store, token_strategy=strategy)
```

To reuse a Redis client you already have, pass it directly: `RedisTokenStrategy(config, client)`.

Token lifetimes come from `access_token_ttl` and `refresh_token_ttl`, and Redis expires the keys itself.

## What is different

- **Tokens are opaque.** They are random strings, not JWTs, so a client can't decode them. The claims stay on the server.
- **Instant revocation.** Logout and refresh rotation delete the token in Redis. A revoked token returns `TokenRevoked` (401), the same as with JWT.
- **Expired tokens look unknown.** Redis removes an expired key, so an expired token returns `InvalidToken` (400), not `TokenExpired`.
- **Redis is on the critical path.** If Redis is unreachable, requests that need a token fail with a server error. Flushing Redis logs everyone out.
- **Roles still refresh at renewal.** As with JWT, a role change reaches an existing token only when it is refreshed. Use `warden.current_user` and check `user.roles` when you need it immediately.
- **What Redis holds.** Keys are `authwarden:token:<sha256 of the token>` and `authwarden:revoked:<sha256 of the token>`. The raw token is never stored. Use a dedicated Redis database or instance for them.

`token_blacklist` only applies to the JWT strategy. Passing it together with `token_strategy` raises `ValueError`.

`warden.jwt_handler` still works and is an alias for `warden.token_strategy`.

## Writing your own strategy

Any object with these three async methods works. There is no base class to inherit.

```python
class MyStrategy:
    async def issue_token_pair(self, user_id, roles=None, scopes=None) -> TokenPair: ...
    async def verify_token(self, token, expected_type="access") -> TokenPayload: ...
    async def blacklist_token(self, token, expected_type="access") -> None: ...
```

`verify_token` returns a `TokenPayload` (`sub`, `jti`, `type`, `roles`, `scopes`, `iat`, `exp`) or raises `InvalidToken`, `TokenExpired` or `TokenRevoked`. `blacklist_token` revokes a token.