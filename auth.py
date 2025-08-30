from flask import current_app, request
from flask_httpauth import HTTPTokenAuth
from webargs.flaskparser import abort

auth = HTTPTokenAuth()


@auth.verify_token
def verify_token(token: str) -> bool | None:
    """
    Basic token authentication that checks against a plaintext token.
    THIS WOULD NOT BE SUITABLE FOR PRODUCTION USE.
    """
    settings_ = current_app.config["SETTINGS"]

    if token == settings_.api_key:
        return True

    return None


def require_login() -> None:
    r"""
    A `before_request` handler to require authentication on all routes.
    """
    auth_ = auth.get_auth()

    if request.method != "OPTIONS":
        password = auth.get_auth_password(auth_)

        user = auth.authenticate(auth_, password)

        if user in (False, None):
            abort(401)
