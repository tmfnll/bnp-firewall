from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any, Generic, TypeVar

from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import Select
from sqlalchemy.orm.interfaces import ORMOption

from db import Base

T = TypeVar("T", bound=Base)


class Repository(Generic[T], ABC):
    """
    Base repository class for common database operations.

    Whilst strictly speaking repositories should completely abstract away the ORM,
    in my experience this is impractical and results in a lot of boilerplate code.

    This class therefore provides a thin abstraction over SQLAlchemy in order to
    encapsulate access to models, ensuring things like the removal of soft-deleted
    items and prefetching of related objects.
    """

    def __init__(self, db: SQLAlchemy, options: list[ORMOption] | None = None):
        if options is None:
            options = self.default_options

        self.options = options
        self.db = db

    @property
    def default_options(self) -> list[ORMOption]:  # pragma: nocover
        return []

    @property
    @abstractmethod
    def model_type(self) -> type[T]:
        raise NotImplementedError()  # pragma: nocover

    def select_all(self) -> Select:
        return self.db.select(self.model_type).options(*self.default_options)

    def select(self) -> Select:
        return self.select_all().where(self.model_type.deleted_at.is_(None))

    def filter(
        self, *, order_by: StrEnum | None = None, **filters: Any
    ) -> Select:
        select_ = self.select()

        for attr, value in filters.items():
            select_ = select_.where(getattr(self.model_type, attr) == value)

        if order_by is not None:
            order_by_value = order_by.value

            if order_by.value.startswith("-"):
                order_by_clause = getattr(
                    self.model_type, order_by_value[1:]
                ).desc()
            else:
                order_by_clause = getattr(self.model_type, order_by_value).asc()

            select_ = select_.order_by(order_by_clause)

        return select_

    def get(self, id_: int) -> T:
        return self.db.session.execute(
            self.select().where(self.model_type.id == id_)
        ).scalar_one()
