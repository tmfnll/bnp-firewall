from flask import Flask
from flask_smorest import Api

from db import db, migrate
from firewalls import models  # noqa: F401 to register models with SQLAlchemy
from firewalls.flask import firewalls
from health import health
from settings import Settings

app = Flask(__name__)

api = Api()


settings = Settings()  # type: ignore[call-arg]


def initialise_app(app_: Flask, settings_: Settings) -> None:
    app_.config["SETTINGS"] = settings_
    app_.config["SQLALCHEMY_DATABASE_URI"] = settings_.db_url
    app_.config["TESTING"] = settings_.test

    app_.config["API_TITLE"] = settings.app_name
    app_.config["API_VERSION"] = settings.version
    app_.config["OPENAPI_VERSION"] = "3.0.3"
    app_.config["OPENAPI_URL_PREFIX"] = "/docs"
    app_.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    app_.config["OPENAPI_SWAGGER_UI_URL"] = (
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@3.25.x/"
    )
    app_.config["API_SPEC_OPTIONS"] = {
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "JWT",
                }
            }
        },
    }

    db.init_app(app_)
    migrate.init_app(app_, db)

    api.init_app(app_)

    api.register_blueprint(firewalls)
    api.register_blueprint(health)


initialise_app(app, settings)
