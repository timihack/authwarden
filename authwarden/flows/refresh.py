"""Token refresh flow."""
from __future__ import annotations

from authwarden.authentication.jwt import JWTHandler
from authwarden.core.config import WardenConfig
from authwarden.exceptions import InvalidToken
from authwarden.models.token import TokenPair
from authwarden.storage.base import AbstractUserStore


async def refresh_flow(
    refresh_token: str,
    *,
    store: AbstractUserStore,
    config: WardenConfig,
    jwt_handler: JWTHandler,
) -> TokenPair:
    """Issue a new token pair from a valid refresh token.

    Rotates the refresh token when ``config.enable_refresh_rotation`` is True.

    Raises:
        TokenExpired: Refresh token expired.
        TokenRevoked: Refresh token revoked.
        InvalidToken: Malformed, wrong type, or user inactive/gone.
    """
    payload = await jwt_handler.verify_token(refresh_token, expected_type="refresh")

    user = await store.get_by_id(payload.sub)
    if user is None or not user.is_active:
        raise InvalidToken("User account is inactive or no longer exists")

    if config.enable_refresh_rotation:
        await jwt_handler.blacklist_token(refresh_token, expected_type="refresh")

    return jwt_handler.create_token_pair(user.id, roles=user.roles, scopes=user.scopes)