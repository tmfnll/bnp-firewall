from factory.alchemy import SQLAlchemyModelFactory

from db import db


class BaseFactory(SQLAlchemyModelFactory):
    class Meta:
        abstract = True
        sqlalchemy_session_persistence = "commit"
        sqlalchemy_session_factory = lambda: db.session
