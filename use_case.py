from abc import ABC, abstractmethod
from logging import Logger, getLogger
from typing import Generic, TypeVar

from flask_sqlalchemy import SQLAlchemy

C = TypeVar("C")
T = TypeVar("T")


class UseCase(Generic[C, T], ABC):
    """
    Use cases represent the entrypoints into our application.  A given request/
    script should only ever call a single use case, which will then orchestrate
    the necessary domain logic as well as handling transactions.

    In a more complete example, we might add additional features to this class
    such as sending of request level metrics and traces or sending of domain
    events.
    """
    def __init__(
        self,
        db: SQLAlchemy,
        logger: Logger | None = None,
    ):
        self.db = db

        self.logger = logger or self.get_logger()

    @classmethod
    def get_logger(cls) -> Logger:
        logger = getLogger(f"{cls.__module__}.{cls.__name__}")

        return logger

    @abstractmethod
    def _execute(self, command: C) -> T:
        raise NotImplementedError()  # pragma: nocover

    def __call__(self, command: C) -> T:
        self.logger.info(f"Executing {type(self).__name__}")

        with self.db.session.begin(nested=True):
            try:
                result = self._execute(command)
            except Exception as exc:
                self.db.session.rollback()

                raise exc

            self.db.session.commit()

        self.logger.info("Done")

        return result
