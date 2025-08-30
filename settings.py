from __future__ import annotations

from enum import StrEnum
from logging import getLogger
from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

logger = getLogger(__name__)


def root_directory() -> Path:
    return Path(__file__).parent


_DEFAULT_APP_NAME = root_directory().name.title()


class Environment(StrEnum):
    LOCAL = "local"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings, frozen=True):  # type: ignore[misc]
    environment: Environment
    version: str

    db_url: str

    app_name: str = Field(default=_DEFAULT_APP_NAME)
    app_root: Path = Field(default_factory=root_directory)

    test: bool = False

    max_per_page: int = 100

    jwt_secret: str

    model_config = SettingsConfigDict(
        env_file=root_directory() / ".env",
        env_prefix="settings_",
        extra="ignore",
    )

    @property
    def is_local(self) -> bool:
        return self.environment is Environment.LOCAL
