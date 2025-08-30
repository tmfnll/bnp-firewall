from flask import Flask
from flask_smorest import Api

from auth import print_jwt_cmd
from converters import IdConverter, id_converter_params
from db import db, migrate
from firewalls import models  # noqa: F401 to register models with SQLAlchemy
from firewalls.flask.views import firewalls
from health import health
from settings import Settings

app = Flask(__name__)

api = Api()


settings = Settings()  # type: ignore[call-arg]


def initialise_app(flask: Flask, settings_: Settings) -> None:
    flask.config["SETTINGS"] = settings_
    flask.config["SQLALCHEMY_DATABASE_URI"] = settings_.db_url
    flask.config["TESTING"] = settings_.test

    flask.config["API_TITLE"] = settings.app_name
    flask.config["API_VERSION"] = settings.version
    flask.config["OPENAPI_VERSION"] = "3.0.3"
    flask.config["OPENAPI_URL_PREFIX"] = "/docs"
    flask.config["OPENAPI_SWAGGER_UI_PATH"] = "/swagger-ui"
    flask.config["OPENAPI_SWAGGER_UI_URL"] = (
        "https://cdn.jsdelivr.net/npm/swagger-ui-dist@3.25.x/"
    )
    flask.config["API_SPEC_OPTIONS"] = {
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {
                    "type": "http",
                    "scheme": "bearer",
                    "bearerFormat": "TEXT",
                }
            }
        },
    }

    db.init_app(flask)
    migrate.init_app(flask, db)

    api.init_app(flask)

    flask.url_map.converters["id"] = IdConverter
    api.register_converter(IdConverter, id_converter_params)

    api.register_blueprint(firewalls)
    api.register_blueprint(health)

    flask.cli.command("jwt")(print_jwt_cmd)


initialise_app(app, settings)
