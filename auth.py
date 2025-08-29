from flask import current_app
from flask_httpauth import HTTPTokenAuth
from webargs.flaskparser import abort

auth = HTTPTokenAuth()


@auth.verify_token
def verify_token(token: str) -> bool | None:
    settings_ = current_app.config["SETTINGS"]

    if token == settings_.api_key:
        return True

    return None


@auth.error_handler
def auth_error(status):
    abort(status)
