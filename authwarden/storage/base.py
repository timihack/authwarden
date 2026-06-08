"""Abstract user store protocol for authwarden.

Consumers implement AbstractUserStore to connect authwarden to any
database or ORM. The library calls only the methods defined here.

Example SQLAlchemy implementation skeleton::

    class SQLAlchemyUserStore:
        async def get_by_id(self, user_id: str) -> UserInDB | None:
            result = await db.execute(select(User).where(User.id == user_id))
            row = result.scalar_one_or_none()
            return UserInDB.model_validate(row) if row else None

        # ... implement remaining methods
"""
from __future__ import annotations

from typing import Protocol, runtime_checkable

from authwarden.models.user import OAuthAccount, UserInDB


@runtime_checkable
class AbstractUserStore(Protocol):
    """Protocol that every user store implementation must satisfy.

    All methods are ``async`` to accommodate both truly async I/O backends
    (SQLAlchemy async, Motor, Prisma) and sync-wrapped ones.
    """

    # ── User CRUD ─────────────────────────────────────────────────────────────

    async def get_by_id(self, user_id: str) -> UserInDB | None:
        """Fetch a user by their UUID.

        Args:
            user_id: The user's UUID string.

        Returns:
            UserInDB if found, None otherwise.
        """
        ...

    async def get_by_email(self, email: str) -> UserInDB | None:
        """Fetch a user by their email address.

        Implementations should perform a case-insensitive lookup.

        Args:
            email: The email address to search for.

        Returns:
            UserInDB if found, None otherwise.
        """
        ...

    async def create(self, user: UserInDB) -> UserInDB:
        """Persist a new user record.

        Args:
            user: Fully populated UserInDB (id and timestamps already set).

        Returns:
            The created UserInDB (may be the same object or a refreshed copy).
        """
        ...

    async def update(self, user: UserInDB) -> UserInDB:
        """Persist changes to an existing user record.

        Callers are responsible for setting ``updated_at`` before calling this.

        Args:
            user: UserInDB with updated fields.

        Returns:
            The updated UserInDB.
        """
        ...

    async def delete(self, user_id: str) -> None:
        """Delete a user record by UUID.

        Args:
            user_id: The UUID of the user to remove.
        """
        ...

    # ── OAuth extensions ──────────────────────────────────────────────────────

    async def get_oauth_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccount | None:
        """Look up a linked OAuth account by provider + provider-side user ID.

        Args:
            provider:         Provider key e.g. ``"google"``, ``"github"``.
            provider_user_id: The stable ID from the provider's token/userinfo.

        Returns:
            OAuthAccount if found, None otherwise.
        """
        ...

    async def get_oauth_accounts_for_user(self, user_id: str) -> list[OAuthAccount]:
        """Return all linked OAuth accounts for a given user.

        Args:
            user_id: The user's UUID.

        Returns:
            List of OAuthAccount records (may be empty).
        """
        ...

    async def create_oauth_account(self, account: OAuthAccount) -> OAuthAccount:
        """Persist a new OAuthAccount record.

        Args:
            account: Fully populated OAuthAccount instance.

        Returns:
            The created OAuthAccount.
        """
        ...

    async def update_oauth_account(self, account: OAuthAccount) -> OAuthAccount:
        """Persist changes to an existing OAuthAccount.

        Args:
            account: OAuthAccount with updated fields.

        Returns:
            The updated OAuthAccount.
        """
        ...

    async def delete_oauth_account(self, user_id: str, provider: str) -> None:
        """Remove a linked OAuth account.

        Args:
            user_id:  Owner's UUID.
            provider: Provider key e.g. ``"google"``.
        """
        ...