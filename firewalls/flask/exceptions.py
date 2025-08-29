from typing import NoReturn

from webargs.flaskparser import abort


def abort_not_found(resource: str, **ids: int) -> NoReturn:
    id_str = " and ".join(f"{key}={value}" for key, value in ids.items())

    if id_str:
        id_str = f"with {id_str} "

    abort(404, message=f"A {resource} {id_str}was not found")


def abort_already_exists(resource: str) -> NoReturn:
    abort(409, message=f"A {resource} with the same attributes already exists")
