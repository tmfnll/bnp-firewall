from datetime import timedelta
from typing import cast

import jwt
import pytest
from flask import Flask
from flask.testing import FlaskCliRunner

from auth import JWT_ALGORITHM, User, decode_jwt, encode_jwt
from conftest import DefaultHeaderFlaskClient
from settings import Settings


@pytest.fixture
def headers(user_jwt: str) -> dict[str, str]:
    return {"Authorization": f"Bearer {user_jwt}"}


@pytest.fixture
def client(app: Flask, headers: dict[str, str]) -> DefaultHeaderFlaskClient:
    return cast(DefaultHeaderFlaskClient, app.test_client(headers=headers))


def test_a_200_is_returned_for_a_valid_jwt(
    client: DefaultHeaderFlaskClient,
) -> None:
    response = client.get("/health/")

    assert response.status_code == 200


class TestWhenJWTIsInvalid:
    @pytest.fixture
    def headers(self) -> dict[str, str]:
        return {"Authorization": "Bearer not_a_jwt"}

    def test_a_401_is_returned(
        self,
        client: DefaultHeaderFlaskClient,
    ) -> None:
        response = client.get("/health/")

        assert response.status_code == 401


class TestWhenJWTIsMissing:
    @pytest.fixture
    def headers(self) -> dict[str, str]:
        return {}

    def test_a_401_is_returned(
        self,
        client: DefaultHeaderFlaskClient,
    ) -> None:
        response = client.get("/health/")

        assert response.status_code == 401


class TestWhenJwtIsExpired:
    @pytest.fixture
    def user_jwt(self, settings: Settings, user: User) -> str:
        return encode_jwt(settings, user, timedelta(seconds=-10))

    def test_a_401_is_returned(
        self,
        client: DefaultHeaderFlaskClient,
    ) -> None:
        response = client.get("/health/")

        assert response.status_code == 401


class TestWhenJwtContainsNoUsername:
    @pytest.fixture
    def user_jwt(self, settings: Settings) -> str:
        return jwt.encode(
            {"not_a_username": "foo"}, settings.jwt_secret, JWT_ALGORITHM
        )

    def test_a_401_is_returned(
        self,
        client: DefaultHeaderFlaskClient,
    ) -> None:
        response = client.get("/health/")

        assert response.status_code == 401


class TestPrintJwtCmd:
    def test_it_prints_a_jwt(
        self, settings: Settings, test_cli_runner: FlaskCliRunner
    ) -> None:
        result = test_cli_runner.invoke(args=["jwt"])

        assert result.exit_code == 0

        decoded_user = decode_jwt(settings, result.output[:-1])  # strip newline

        assert decoded_user == User("test")
