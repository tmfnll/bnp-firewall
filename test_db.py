from typing import Generator
from unittest.mock import MagicMock, patch

import pytest
from flask import Flask
from flask.testing import FlaskCliRunner

from settings import Environment, Settings


@pytest.fixture
def db() -> Generator[MagicMock]:
    with patch("db.db") as mock:
        yield mock


def test_recreate_db(test_cli_runner: FlaskCliRunner, db: MagicMock) -> None:
    result = test_cli_runner.invoke(args=["recreate-db"])

    assert result.exit_code == 0

    db.drop_all.assert_called_once_with()
    db.create_all.assert_called_once_with()


class TestWhenNotLocal:
    @pytest.fixture(autouse=True)
    def override_settings(
        self, app: Flask, settings: Settings, new_environment: Environment
    ) -> Generator[None]:
        app.config["SETTINGS"] = settings.model_copy(
            update={"environment": new_environment}
        )

        yield

        app.config["SETTINGS"] = settings

    @pytest.mark.parametrize(
        "new_environment", set(Environment) - {Environment.LOCAL}
    )
    def test_recreate_db_raises_a_runtime_error(
        self, test_cli_runner: FlaskCliRunner, db: MagicMock
    ) -> None:
        with pytest.raises(
            RuntimeError,
            match="Cannot recreate the database unless in the local environment",
        ):
            test_cli_runner.invoke(args=["recreate-db"])

        db.drop_all.assert_not_called()
        db.create_all.assert_not_called()
