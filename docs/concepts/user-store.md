# User Store (Database)

`AbstractUserStore` is a `Protocol`, not a base class — any object with the right async methods satisfies it. There's no inheritance required and no ORM lock-in.

```python
@runtime_checkable
class AbstractUserStore(Protocol):
    async def get_by_id(self, user_id: str) -> UserInDB | None: ...
    async def get_by_email(self, email: str) -> UserInDB | None: ...
    async def get_by_username(self, username: str) -> UserInDB | None: ...
    async def get_by_phone(self, phone: str) -> UserInDB | None: ...
    async def create(self, user: UserInDB) -> UserInDB: ...
    async def update(self, user: UserInDB) -> UserInDB: ...
    async def delete(self, user_id: str) -> None: ...

    async def get_oauth_account(self, provider: str, provider_user_id: str) -> OAuthAccount | None: ...
    async def get_oauth_accounts_for_user(self, user_id: str) -> list[OAuthAccount]: ...
    async def create_oauth_account(self, account: OAuthAccount) -> OAuthAccount: ...
    async def update_oauth_account(self, account: OAuthAccount) -> OAuthAccount: ...
    async def delete_oauth_account(self, user_id: str, provider: str) -> None: ...
```

`get_by_username`/`get_by_phone` only need real implementations if you actually use those fields (as login identifiers, or for SMS verification) — otherwise returning `None` unconditionally is fine.

`UserInDB` has `model_config = ConfigDict(from_attributes=True)`, so it can validate directly from an ORM row as long as field names line up — `UserInDB.model_validate(row)`.

## SQLAlchemy (built in)

```bash
pip install "authwarden[sqlalchemy]" asyncpg   # or aiosqlite for SQLite
```

Requires SQLAlchemy 2.0 or later in async mode. You install the database driver yourself.

```python
from contextlib import asynccontextmanager

from fastapi import FastAPI
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from authwarden import AuthWarden, WardenConfig
from authwarden.storage.sqlalchemy import SQLAlchemyUserStore, create_tables

engine = create_async_engine("postgresql+asyncpg://user:password@localhost/app")
session_factory = async_sessionmaker(engine, expire_on_commit=False)

warden = AuthWarden(
    config=WardenConfig(secret_key="change-me-to-a-real-32-byte-secret"),
    user_store=SQLAlchemyUserStore(session_factory),
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_tables(engine)
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)
app.include_router(warden.router, prefix="/auth", tags=["auth"])
```

What to know:

- **Tables.** `authwarden_users` and `authwarden_oauth_accounts`. The prefix keeps them away from your own `users` table. `create_tables(engine)` creates them if missing.
- **Migrations.** Import `Base` from `authwarden.storage.sqlalchemy` and include `Base.metadata` in your Alembic `target_metadata`. On PostgreSQL, autogenerate also creates the case-insensitive unique indexes on email and username. On SQLite, Alembic can't reflect those two indexes and skips them with a warning, so use `create_tables` or add them by hand.
- **Email and username** are matched case-insensitively, and uniqueness is enforced the same way by the database.
- **Datetimes** are stored in UTC and come back timezone-aware on every database, including SQLite.
- **Your own fields.** Put them in `extra_data`, which is stored as JSON. Fields you add by subclassing `UserInDB` are not persisted by this store. If you need real columns for them, write your own store.
- **Duplicates.** The register flow checks email, username and phone first, so the database constraint only triggers on a race. It then raises SQLAlchemy's `IntegrityError`.
- **Tested on** SQLite and PostgreSQL, with SQLAlchemy 2.0 and 2.1. Other databases may work but are not tested.

Everything below this point is for databases that don't have a built-in store.

## MongoDB with Beanie

Beanie `Document` classes are Pydantic-based, so you can often skip the conversion step entirely:

```python
from beanie import Document
from authwarden import UserInDB

class UserDocument(UserInDB, Document):
    class Settings:
        name = "users"

class BeanieUserStore:
    async def get_by_id(self, user_id: str) -> UserInDB | None:
        return await UserDocument.get(user_id)

    async def get_by_email(self, email: str) -> UserInDB | None:
        return await UserDocument.find_one(UserDocument.email == email)

    async def create(self, user: UserInDB) -> UserInDB:
        doc = UserDocument(**user.model_dump())
        await doc.insert()
        return doc

    async def update(self, user: UserInDB) -> UserInDB:
        doc = await UserDocument.get(user.id)
        await doc.set(user.model_dump())
        return doc

    # ...
```

## SQLModel with SQLite

This adapter implements all 12 methods in `AbstractUserStore` with an asynchronous SQLite engine and `AsyncSession`. It was tested with SQLModel 0.0.45 to 0.0.48 and authwarden 1.2.0 on SQLite.

Install:

```bash
pip install "sqlmodel>=0.0.45" "sqlalchemy[asyncio]" aiosqlite
```

Save as `sqlmodel_store.py`:

```python
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Column, DateTime, Index, JSON, String, UniqueConstraint, func
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.types import TypeDecorator
from sqlmodel import Field, SQLModel, select
from sqlmodel.ext.asyncio.session import AsyncSession

from authwarden import OAuthAccount, UserInDB


class UTCDateTime(TypeDecorator):
    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is None:
            return None
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    def process_result_value(self, value: datetime | None, dialect: Any) -> datetime | None:
        if value is not None and value.tzinfo is None:
            return value.replace(tzinfo=timezone.utc)
        return value


class UserTable(SQLModel, table=True):
    __tablename__ = "authwarden_users"
    __table_args__ = (
        Index("uq_authwarden_sqlmodel_users_email", func.lower(Column("email")), unique=True),
        Index("uq_authwarden_sqlmodel_users_username", func.lower(Column("username")), unique=True),
    )

    id: str = Field(primary_key=True)
    email: str = Field(sa_column=Column(String(320), nullable=False))
    username: str | None = Field(default=None, sa_column=Column(String(255), nullable=True))
    full_name: str | None = None
    hashed_password: str | None = None
    phone_number: str | None = Field(default=None, index=True, unique=True)
    phone_verified: bool = False
    is_active: bool = True
    is_verified: bool = False
    is_superuser: bool = False
    roles: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    scopes: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    extra_data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON, nullable=False))
    mfa_enabled: bool = False
    mfa_secret: str | None = None
    mfa_pending_secret: str | None = None
    backup_codes: list[str] = Field(default_factory=list, sa_column=Column(JSON, nullable=False))
    last_verification_sent_at: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    verification_otp_hash: str | None = None
    verification_otp_expires_at: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    verification_otp_attempts: int = 0
    last_reset_request_at: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    reset_token_hash: str | None = None
    reset_token_used_at: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    reset_otp_hash: str | None = None
    reset_otp_expires_at: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    reset_otp_attempts: int = 0
    failed_login_attempts: int = 0
    locked_until: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    created_at: datetime = Field(sa_column=Column(UTCDateTime(), nullable=False))
    updated_at: datetime = Field(sa_column=Column(UTCDateTime(), nullable=False))


class OAuthAccountTable(SQLModel, table=True):
    __tablename__ = "authwarden_oauth_accounts"
    __table_args__ = (UniqueConstraint("provider", "provider_user_id"),)

    id: str = Field(primary_key=True)
    user_id: str = Field(foreign_key="authwarden_users.id", index=True)
    provider: str = Field(index=True)
    provider_user_id: str
    email: str | None = None
    access_token: str | None = None
    refresh_token: str | None = None
    token_expires_at: datetime | None = Field(default=None, sa_column=Column(UTCDateTime(), nullable=True))
    created_at: datetime = Field(sa_column=Column(UTCDateTime(), nullable=False))
    updated_at: datetime = Field(sa_column=Column(UTCDateTime(), nullable=False))


class SQLModelUserStore:
    def __init__(self, session_factory: async_sessionmaker[AsyncSession]) -> None:
        self.session_factory = session_factory

    @staticmethod
    def _user(row: UserTable | None) -> UserInDB | None:
        return UserInDB.model_validate(row, from_attributes=True) if row is not None else None

    @staticmethod
    def _account(row: OAuthAccountTable | None) -> OAuthAccount | None:
        return OAuthAccount.model_validate(row, from_attributes=True) if row is not None else None

    async def get_by_id(self, user_id: str) -> UserInDB | None:
        async with self.session_factory() as session:
            return self._user(await session.get(UserTable, user_id))

    async def get_by_email(self, email: str) -> UserInDB | None:
        statement = select(UserTable).where(func.lower(UserTable.email) == email.lower())
        async with self.session_factory() as session:
            result = await session.execute(statement)
            return self._user(result.scalar_one_or_none())

    async def get_by_username(self, username: str) -> UserInDB | None:
        statement = select(UserTable).where(func.lower(UserTable.username) == username.lower())
        async with self.session_factory() as session:
            result = await session.execute(statement)
            return self._user(result.scalar_one_or_none())

    async def get_by_phone(self, phone: str) -> UserInDB | None:
        statement = select(UserTable).where(UserTable.phone_number == phone)
        async with self.session_factory() as session:
            result = await session.execute(statement)
            return self._user(result.scalar_one_or_none())

    async def create(self, user: UserInDB) -> UserInDB:
        row = UserTable.model_validate(user.model_dump())
        async with self.session_factory() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return self._user(row)

    async def update(self, user: UserInDB) -> UserInDB:
        async with self.session_factory() as session:
            row = await session.get(UserTable, user.id)
            if row is None:
                raise ValueError("User does not exist")
            for key, value in user.model_dump().items():
                setattr(row, key, value)
            await session.commit()
            await session.refresh(row)
            return self._user(row)

    async def delete(self, user_id: str) -> None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(OAuthAccountTable).where(OAuthAccountTable.user_id == user_id)
            )
            for account in result.scalars():
                await session.delete(account)
            row = await session.get(UserTable, user_id)
            if row is not None:
                await session.delete(row)
            await session.commit()

    async def get_oauth_account(
        self, provider: str, provider_user_id: str
    ) -> OAuthAccount | None:
        statement = select(OAuthAccountTable).where(
            OAuthAccountTable.provider == provider,
            OAuthAccountTable.provider_user_id == provider_user_id,
        )
        async with self.session_factory() as session:
            result = await session.execute(statement)
            return self._account(result.scalar_one_or_none())

    async def get_oauth_accounts_for_user(self, user_id: str) -> list[OAuthAccount]:
        statement = select(OAuthAccountTable).where(OAuthAccountTable.user_id == user_id)
        async with self.session_factory() as session:
            result = await session.execute(statement)
            return [self._account(row) for row in result.scalars()]

    async def create_oauth_account(self, account: OAuthAccount) -> OAuthAccount:
        row = OAuthAccountTable.model_validate(account.model_dump())
        async with self.session_factory() as session:
            session.add(row)
            await session.commit()
            await session.refresh(row)
            return self._account(row)

    async def update_oauth_account(self, account: OAuthAccount) -> OAuthAccount:
        async with self.session_factory() as session:
            row = await session.get(OAuthAccountTable, account.id)
            if row is None:
                raise ValueError("OAuth account does not exist")
            for key, value in account.model_dump().items():
                setattr(row, key, value)
            await session.commit()
            await session.refresh(row)
            return self._account(row)

    async def delete_oauth_account(self, user_id: str, provider: str) -> None:
        statement = select(OAuthAccountTable).where(
            OAuthAccountTable.user_id == user_id,
            OAuthAccountTable.provider == provider,
        )
        async with self.session_factory() as session:
            result = await session.execute(statement)
            for row in result.scalars():
                await session.delete(row)
            await session.commit()


engine = create_async_engine("sqlite+aiosqlite:///./authwarden.db")
session_factory = async_sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
store = SQLModelUserStore(session_factory)


async def init_db() -> None:
    async with engine.begin() as connection:
        await connection.run_sync(SQLModel.metadata.create_all)
```

The adapter uses JSON columns for list/dictionary fields, UTC-normalized datetime columns, case-insensitive unique email and username indexes, a unique phone number, and a unique `(provider, provider_user_id)` pair. Both tables use the `authwarden_` prefix to avoid colliding with application tables.

### Exercise the HTTP API

Save this wiring as `main.py`:

```python
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI
from authwarden import AuthWarden, WardenConfig
from sqlmodel_store import engine, init_db, store

warden = AuthWarden(
    config=WardenConfig(
        secret_key="replace-this-with-a-long-random-secret",
        require_email_verification=False,
    ),
    user_store=store,
)


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    yield
    await engine.dispose()


app = FastAPI(lifespan=lifespan)
app.include_router(warden.router, prefix="/auth", tags=["auth"])


@app.get("/profile")
async def profile(user=Depends(warden.current_user)):
    return {"id": user.id, "email": user.email}
```

Start the app with `uvicorn main:app --reload`. In `/docs`, register a user, check duplicate-email rejection, log in, exercise the lockout flow, and call `/profile` with the returned bearer token. Try an OAuth provider if configured. Restart the app and confirm the user persists in `authwarden.db`.

**Compatibility note:** the HTTP walkthrough was tested with authwarden 1.1.3 and 1.2.0 using SQLModel 0.0.45 and 0.0.48.

## Tortoise ORM

Tortoise models aren't Pydantic-native, so map fields explicitly rather than relying on `model_validate`:

```python
from tortoise.models import Model
from tortoise import fields
from authwarden import UserInDB

class UserModel(Model):
    id = fields.CharField(pk=True, max_length=36)
    email = fields.CharField(max_length=255, unique=True)
    hashed_password = fields.CharField(max_length=255, null=True)
    is_active = fields.BooleanField(default=True)
    # ... remaining fields

class TortoiseUserStore:
    async def get_by_email(self, email: str) -> UserInDB | None:
        row = await UserModel.get_or_none(email=email)
        if row is None:
            return None
        return UserInDB(
            id=row.id, email=row.email, hashed_password=row.hashed_password,
            is_active=row.is_active,
            # ... remaining fields
        )
    # ...
```