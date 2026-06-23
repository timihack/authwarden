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
from authwarden.storage.base import AbstractUserStore


class MemoryUserStore:
  """A fully in-memory implementation of the AbstractUserStore protocol.

  Satisfies the protocol via structural subtyping (no explicit inheritance
  required). All methods are async to match the protocol signature.
  """

  def __init__(self) -> None:
      self._users: dict[str, UserInDB] = {}
      self._email_index: dict[str, str] = {}          # email.lower() → user_id
      self._username_index: dict[str, str] = {}       # username.lower() → user_id
      self._phone_index: dict[str, str] = {}          # phone → user_id
      self._oauth_accounts: dict[str, OAuthAccount] = {}  # account.id → OAuthAccount


  # ---- Helpers --------------------------------------------------------------------
  def _remove_indexes(self, user: UserInDB) -> None:
      self._email_index.pop(user.email.lower(), None)
      if user.username:
          self._username_index.pop(user.username.lower(), None)
      if user.phone_number:
          self._phone_index.pop(user.phone_number, None)

  def _add_indexes(self, user: UserInDB) -> None:
      self._email_index[user.email.lower()] = user.id
      if user.username:
          self._username_index[user.username.lower()] = user.id
      if user.phone_number:
          self._phone_index[user.phone_number] = user.id

  # ── User CRUD ─────────────────────────────────────────────────────────────

  async def get_by_id(self, user_id: str) -> UserInDB | None:
      """Return the user with the given UUID, or None."""
      return self._users.get(user_id)

  async def get_by_email(self, email: str) -> UserInDB | None:
      """Return the user with the given email (case-insensitive), or None."""
      uid = self._email_index.get(email.lower())
      return self._users.get(uid) if uid else None
  
  async def get_by_username(self, username: str) -> UserInDB | None:
      """Return the user with the given username (case-insensitive), or None."""
      uid = self._username_index.get(username.lower())
      return self._users.get(uid) if uid else None

  async def get_by_phone(self, phone: str) -> UserInDB | None:
      """Return the user with the given phone number, or None."""
      uid = self._phone_index.get(phone)
      return self._users.get(uid) if uid else None

  async def create(self, user: UserInDB) -> UserInDB:
      """Store a new user and update the email index.

      Args:
          user: Fully populated UserInDB instance.

      Returns:
          The same UserInDB instance.
      """
      self._users[user.id] = user
      self._add_indexes(user)
      return user

  async def update(self, user: UserInDB) -> UserInDB:
    """Overwrite the stored user record and refresh the email index.

    Handles email changes by cleaning up the old index entry.
    Compares against the previously stored copy, not the incoming object,
    since the caller may have mutated the same instance in place.

    Args:
        user: UserInDB with updated fields.

    Returns:
        The updated UserInDB instance.
    """
    # Scan index for any stale entries pointing to this user_id and clean up
    stale_emails = [e for e, uid in self._email_index.items() if uid == user.id and e != user.email.lower()]
    for e in stale_emails:
        del self._email_index[e]
    stale_usernames = [u for u, uid in self._username_index.items() if uid == user.id and u != (user.username or "").lower()]
    for u in stale_usernames:
        del self._username_index[u]
    stale_phones = [p for p, uid in self._phone_index.items() if uid == user.id and p != user.phone_number]
    for p in stale_phones:
        del self._phone_index[p]

    self._users[user.id] = user
    self._add_indexes(user)
    return user

  async def delete(self, user_id: str) -> None:
    """Remove a user and their email index entry.

    Args:
        user_id: UUID of the user to remove.
    """
    user = self._users.pop(user_id, None)
    if user:
        self._remove_indexes(user)


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
      self._users.clear(); self._email_index.clear()
      self._username_index.clear(); self._phone_index.clear()
      self._oauth_accounts.clear()

  @property
  def user_count(self) -> int:
      """Return the total number of stored users."""
      return len(self._users)
  
assert isinstance(MemoryUserStore(), AbstractUserStore), "MemoryUserStore does not satisfy AbstractUserStore protocol"