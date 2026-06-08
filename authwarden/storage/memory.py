"""In-memory user store for testing and quick-start development.

Not suitable for production — all data is lost on process restart and
there is no inter-process or thread safety beyond Python's GIL.

Usage::

    from authwarden.storage.memory import MemoryUserStore
    from authwarden import AuthWarden, WardenConfig

    store = MemoryUserStore()
    warden = AuthWarden(config=WardenConfig(secret_key="..."), user_store=store)
"""
from __future__ import annotations

from authwarden.models.user import OAuthAccount, UserInDB


class MemoryUserStore:
    """A fully in-memory implementation of the AbstractUserStore protocol.

    Satisfies the protocol via structural subtyping (no explicit inheritance
    required). All methods are async to match the protocol signature.
    """

    def __init__(self) -> None:
        self._users: dict[str, UserInDB] = {}
        self._email_index: dict[str, str] = {}          # email.lower() → user_id
        self._oauth_accounts: dict[str, OAuthAccount] = {}  # account.id → OAuthAccount

    # ── User CRUD ─────────────────────────────────────────────────────────────

    async def get_by_id(self, user_id: str) -> UserInDB | None:
        """Return the user with the given UUID, or None."""
        return self._users.get(user_id)

    async def get_by_email(self, email: str) -> UserInDB | None:
        """Return the user with the given email (case-insensitive), or None."""
        user_id = self._email_index.get(email.lower())
        if user_id is None:
            return None
        return self._users.get(user_id)

    async def create(self, user: UserInDB) -> UserInDB:
        """Store a new user and update the email index.

        Args:
            user: Fully populated UserInDB instance.

        Returns:
            The same UserInDB instance.
        """
        self._users[user.id] = user
        self._email_index[user.email.lower()] = user.id
        return user

    async def update(self, user: UserInDB) -> UserInDB:
        """Overwrite the stored user record and refresh the email index.

        Handles email changes by cleaning up the old index entry.

        Args:
            user: UserInDB with updated fields.

        Returns:
            The updated UserInDB instance.
        """
        existing = self._users.get(user.id)
        if existing and existing.email.lower() != user.email.lower():
            self._email_index.pop(existing.email.lower(), None)
        self._users[user.id] = user
        self._email_index[user.email.lower()] = user.id
        return user

    async def delete(self, user_id: str) -> None:
        """Remove a user and their email index entry.

        Args:
            user_id: UUID of the user to remove.
        """
        user = self._users.pop(user_id, None)
        if user:
            self._email_index.pop(user.email.lower(), None)

    # ── OAuth accounts ────────────────────────────────────────────────────────

    async def get_oauth_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccount | None:
        """Look up an OAuth account by (provider, provider_user_id).

        Args:
            provider:         Provider key e.g. ``"google"``.
            provider_user_id: Stable user ID from the provider.

        Returns:
            OAuthAccount if found, None otherwise.
        """
        for account in self._oauth_accounts.values():
            if (
                account.provider == provider
                and account.provider_user_id == provider_user_id
            ):
                return account
        return None

    async def get_oauth_accounts_for_user(self, user_id: str) -> list[OAuthAccount]:
        """Return all OAuth accounts linked to a given user.

        Args:
            user_id: Owner's UUID.

        Returns:
            List of OAuthAccount records (may be empty).
        """
        return [a for a in self._oauth_accounts.values() if a.user_id == user_id]

    async def create_oauth_account(self, account: OAuthAccount) -> OAuthAccount:
        """Store a new OAuthAccount.

        Args:
            account: Fully populated OAuthAccount instance.

        Returns:
            The same OAuthAccount instance.
        """
        self._oauth_accounts[account.id] = account
        return account

    async def update_oauth_account(self, account: OAuthAccount) -> OAuthAccount:
        """Overwrite an existing OAuthAccount.

        Args:
            account: OAuthAccount with updated fields.

        Returns:
            The updated OAuthAccount instance.
        """
        self._oauth_accounts[account.id] = account
        return account

    async def delete_oauth_account(self, user_id: str, provider: str) -> None:
        """Remove the OAuth account matching (user_id, provider).

        Args:
            user_id:  Owner's UUID.
            provider: Provider key e.g. ``"google"``.
        """
        to_delete = [
            acc_id
            for acc_id, acc in self._oauth_accounts.items()
            if acc.user_id == user_id and acc.provider == provider
        ]
        for acc_id in to_delete:
            del self._oauth_accounts[acc_id]

    # ── Test helpers ──────────────────────────────────────────────────────────

    def clear(self) -> None:
        """Reset the store to empty state. Useful between test cases."""
        self._users.clear()
        self._email_index.clear()
        self._oauth_accounts.clear()

    @property
    def user_count(self) -> int:
        """Return the total number of stored users."""
        return len(self._users)