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

## SQLAlchemy (async)

```python
from sqlalchemy import select
from authwarden import UserInDB
from authwarden.models.user import OAuthAccount

class SQLAlchemyUserStore:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    async def get_by_id(self, user_id: str) -> UserInDB | None:
        async with self.session_factory() as session:
            row = await session.get(UserModel, user_id)
            return UserInDB.model_validate(row) if row else None

    async def get_by_email(self, email: str) -> UserInDB | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.email == email)
            )
            row = result.scalar_one_or_none()
            return UserInDB.model_validate(row) if row else None

    async def get_by_username(self, username: str) -> UserInDB | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.username == username)
            )
            row = result.scalar_one_or_none()
            return UserInDB.model_validate(row) if row else None

    async def get_by_phone(self, phone: str) -> UserInDB | None:
        async with self.session_factory() as session:
            result = await session.execute(
                select(UserModel).where(UserModel.phone_number == phone)
            )
            row = result.scalar_one_or_none()
            return UserInDB.model_validate(row) if row else None

    async def create(self, user: UserInDB) -> UserInDB:
        async with self.session_factory() as session:
            row = UserModel(**user.model_dump())
            session.add(row)
            await session.commit()
            return user

    async def update(self, user: UserInDB) -> UserInDB:
        async with self.session_factory() as session:
            row = await session.get(UserModel, user.id)
            for key, value in user.model_dump().items():
                setattr(row, key, value)
            await session.commit()
            return user

    async def delete(self, user_id: str) -> None:
        async with self.session_factory() as session:
            row = await session.get(UserModel, user_id)
            if row:
                await session.delete(row)
                await session.commit()

    # OAuth account methods follow the same pattern against an OAuthAccountModel table
    ...
```

Your `UserModel` columns need to match `UserInDB`'s fields (or close enough for `model_validate` to map them) — `id`, `email`, `username`, `phone_number`, `hashed_password`, `is_active`, `is_verified`, `roles`, `scopes`, `mfa_secret`, `backup_codes`, and so on.

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

## SQLModel

SQLModel classes are already Pydantic models, so the adapter is the thinnest of all three:

```python
from sqlmodel import SQLModel, Field, select
from authwarden import UserInDB

class UserTable(UserInDB, SQLModel, table=True):
    __tablename__ = "users"

class SQLModelUserStore:
    def __init__(self, session_factory):
        self.session_factory = session_factory

    async def get_by_email(self, email: str) -> UserInDB | None:
        async with self.session_factory() as session:
            result = await session.execute(select(UserTable).where(UserTable.email == email))
            return result.scalar_one_or_none()
    # ...
```

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
