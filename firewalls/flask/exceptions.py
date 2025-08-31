from typing import NoReturn

from sqlalchemy.exc import IntegrityError
from webargs.flaskparser import abort


def abort_not_found(resource: str, **ids: int) -> NoReturn:
    id_str = " and ".join(f"{key}={value}" for key, value in ids.items())

    if id_str:
        id_str = f"with {id_str} "

    abort(404, message=f"A {resource} {id_str}was not found")


def abort_already_exists(resource: str) -> NoReturn:
    abort(409, message=f"A {resource} with the same attributes already exists")


def abort_integrity_error(
    resource: str, integrity_error: IntegrityError
) -> NoReturn:
    if "UNIQUE constraint failed" in str(integrity_error.orig):
        abort_already_exists(resource)

    # An unexpected integrity error has occurred, re-raise it
    raise integrity_error  # pragma: no cover
