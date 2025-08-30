from datetime import datetime, timezone
from typing import Self, TypeAlias

from flask import current_app
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import DateTime, func
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    mapped_column,
)


class Base(DeclarativeBase):
    id: Mapped[int] = mapped_column(primary_key=True, index=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), index=True, server_default=func.now()
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        index=True,
        server_default=func.now(),
        onupdate=func.now(),
    )

    deleted_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), index=True, nullable=True
    )

    @property
    def is_deleted(self) -> bool:
        return self.deleted_at is not None

    def soft_delete(self, at: datetime | None = None) -> Self:
        self.deleted_at = at or datetime.now(tz=timezone.utc)

        return self


db = SQLAlchemy(model_class=Base)
migrate = Migrate()

BaseModel: TypeAlias = db.Model  # type: ignore[name-defined]


def recreate_db_command() -> None:
    settings_ = current_app.config["SETTINGS"]

    if not settings_.is_local:
        raise RuntimeError(
            "Cannot recreate the database unless in the local environment"
        )

    db.drop_all()
    db.create_all()
