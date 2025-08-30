from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import click
import jwt
from flask import current_app, g, request
from flask_httpauth import HTTPTokenAuth
from webargs.flaskparser import abort

from settings import Settings

auth = HTTPTokenAuth()


@auth.verify_token
def verify_token(token: str) -> User | None:
    """
    Verity that the JWT provided is valid and return the associated user.
    """
    settings_ = current_app.config["SETTINGS"]

    try:
        return decode_jwt(settings_, token)
    except AuthenticationError:
        return None


def require_login() -> None:
    r"""
    A `before_request` handler to require authentication on all routes.
    """
    auth_ = auth.get_auth()

    if request.method != "OPTIONS":
        password = auth.get_auth_password(auth_)

        user = auth.authenticate(auth_, password)

        if user is None:
            abort(401)

        g.flask_httpauth_user = g.user = user

        current_app.logger.info(
            f"Authenticated as user: {user.username}", extra={"user": user}
        )


@dataclass(frozen=True)
class User:
    username: str


JWT_ALGORITHM = "HS256"


def encode_jwt(
    settings: Settings, user: User, duration: timedelta = timedelta(hours=1)
) -> str:
    expiry_datetime = datetime.now(tz=timezone.utc) + duration

    return jwt.encode(
        {"username": user.username, "exp": expiry_datetime.timestamp()},
        settings.jwt_secret,
        algorithm=JWT_ALGORITHM,
    )


class AuthenticationError(Exception):
    pass


def decode_jwt(settings: Settings, token: str) -> User:
    try:
        payload = jwt.decode(
            token, settings.jwt_secret, algorithms=[JWT_ALGORITHM]
        )
    except jwt.InvalidTokenError as exc:
        raise AuthenticationError("Invalid token") from exc

    try:
        return User(username=payload["username"])
    except KeyError as exc:
        raise AuthenticationError("Invalid token payload") from exc


@click.argument("username", default="test")
def print_jwt_cmd(username: str) -> None:
    settings_ = current_app.config["SETTINGS"]

    print(
        encode_jwt(
            settings_, User(username=username), duration=timedelta(days=30)
        )
    )
