from typing import Any, Generator, cast

import pytest
from flask import Flask
from flask.testing import FlaskClient, FlaskCliRunner
from flask_sqlalchemy import SQLAlchemy
from flask_sqlalchemy.session import Session
from sqlalchemy.orm import scoped_session

from app import initialise_app
from auth import User, encode_jwt
from db import db
from settings import Settings


@pytest.fixture(scope="session")
def test_db_url() -> str:
    return "sqlite:///test_database.db"


@pytest.fixture(scope="session")
def settings(test_db_url: str) -> Settings:
    return Settings(db_url=test_db_url, test=True)  # type: ignore[call-arg]


@pytest.fixture(autouse=True, scope="session")
def app(settings: Settings) -> Generator[Flask]:
    app = Flask(__name__)

    app.test_client_class = DefaultHeaderFlaskClient

    initialise_app(app, settings)

    yield app


@pytest.fixture
def app_context(app: Flask) -> Generator[Flask]:
    with app.app_context():
        yield app


@pytest.fixture
def db_(
    app_context: Flask,
    settings: Settings,
) -> Generator[SQLAlchemy]:
    db.drop_all()

    db.create_all()

    yield db


@pytest.fixture
def test_cli_runner(app: Flask) -> FlaskCliRunner:
    return app.test_cli_runner(catch_exceptions=False)


class DefaultHeaderFlaskClient(FlaskClient):
    def __init__(
        self, *args: Any, headers: dict[str, str] | None = None, **kwargs: Any
    ):
        super().__init__(*args, **kwargs)
        self._headers = headers or {}

    def open(self, *args: Any, headers: Any = None, **kwargs):
        headers = headers or {}

        headers.update(self._headers)

        return super().open(*args, headers=headers, **kwargs)


@pytest.fixture
def user() -> User:
    return User(username="test_user")


@pytest.fixture
def user_jwt(settings: Settings, user: User) -> str:
    return encode_jwt(settings, user)


@pytest.fixture
def auth_headers(settings: Settings, user_jwt: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user_jwt}"}


@pytest.fixture
def client(
    app: Flask, auth_headers: dict[str, str]
) -> DefaultHeaderFlaskClient:
    return cast(DefaultHeaderFlaskClient, app.test_client(headers=auth_headers))


@pytest.fixture
def unauthenticated_client(app: Flask) -> DefaultHeaderFlaskClient:
    return cast(DefaultHeaderFlaskClient, app.test_client())


@pytest.fixture(autouse=True)
def session(db_: SQLAlchemy) -> Generator[scoped_session[Session]]:
    session = db_.session

    session.begin_nested()

    yield session

    session.rollback()
