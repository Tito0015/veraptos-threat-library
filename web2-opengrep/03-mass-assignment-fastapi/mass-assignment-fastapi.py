from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session


class UserUpdate(BaseModel):
    model_config = ConfigDict(extra="allow")
    name: str | None = None


class User(BaseModel):
    is_admin: bool = False
    name: str = ""


class DbUser:
    is_admin: bool
    name: str


def update_user_vuln(db: Session, user: DbUser, body: UserUpdate):
    data = body.model_dump()
    for key, val in data.items():
        # ruleid: mass-assignment-fastapi
        setattr(user, key, val)


def create_user_vuln(body: UserUpdate) -> User:
    # ruleid: mass-assignment-fastapi
    return User(**body.model_dump())


ALLOWED = {"name"}


def update_user_safe(db: Session, user: DbUser, body: UserUpdate):
    data = body.model_dump(include=ALLOWED)
    for key, val in data.items():
        # ok: mass-assignment-fastapi
        setattr(user, key, val)


def update_user_allowlist(db: Session, user: DbUser, body: UserUpdate):
    for key in ALLOWED:
        # ok: mass-assignment-fastapi
        setattr(user, key, getattr(body, key))
