from flask import current_app
from flask_httpauth import HTTPTokenAuth

auth = HTTPTokenAuth()


@auth.verify_token
def verify_token(token: str) -> bool | None:
    settings_ = current_app.config["SETTINGS"]

    if token == settings_.api_key:
        return True

    return None
