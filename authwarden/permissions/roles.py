"""Role-based access control for authwarden."""
from __future__ import annotations

from authwarden.exceptions import ForbiddenError
from authwarden.models.token import TokenPayload


# Role hierarchy — higher index = higher privilege
# A user with a higher role implicitly has all lower roles
ROLE_HIERARCHY: list[str] = ["guest", "user", "moderator", "admin", "superadmin"]


def role_rank(role: str) -> int:
    """Return the hierarchy rank of a role (higher = more privilege)."""
    try:
        return ROLE_HIERARCHY.index(role)
    except ValueError:
        return -1


def has_role(payload: TokenPayload, *required_roles: str, require_all: bool = False) -> bool:
    """Check whether the token payload satisfies role requirements.

    Args:
        payload:       Decoded JWT payload containing roles.
        required_roles: Roles to check.
        require_all:   If True, all roles must be present.
                       If False (default), any one role is sufficient.

    Returns:
        True if the requirement is satisfied, False otherwise.
    """
    if require_all:
        return all(r in payload.roles for r in required_roles)
    return any(r in payload.roles for r in required_roles)


def has_min_role(payload: TokenPayload, min_role: str) -> bool:
    """Check whether the user has at least the given role by hierarchy.

    Args:
        payload:  Decoded JWT payload.
        min_role: Minimum required role in the hierarchy.

    Returns:
        True if any of the user's roles meets or exceeds min_role.
    """
    min_rank = role_rank(min_role)
    return any(role_rank(r) >= min_rank for r in payload.roles)


def require_roles(payload: TokenPayload, *roles: str, require_all: bool = False) -> None:
    """Assert that the token payload satisfies role requirements.

    Raises:
        ForbiddenError: If the role check fails.
    """
    if not has_role(payload, *roles, require_all=require_all):
        raise ForbiddenError(
            f"Required role(s): {', '.join(roles)}. "
            f"You have: {', '.join(payload.roles) or 'none'}."
        )


def require_min_role(payload: TokenPayload, min_role: str) -> None:
    """Assert that the user meets the minimum role hierarchy level.

    Raises:
        ForbiddenError: If the user's roles are all below min_role.
    """
    if not has_min_role(payload, min_role):
        raise ForbiddenError(
            f"Minimum role required: {min_role}. "
            f"You have: {', '.join(payload.roles) or 'none'}."
        )