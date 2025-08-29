from typing import Any

from werkzeug.routing import IntegerConverter, Map

SQLITE_MAX_ID_SIZE = (2**63) - 1  # Ensure that IDs are not too big for SQLite


class IdConverter(IntegerConverter):
    def __init__(
        self,
        map: Map,
    ) -> None:
        super().__init__(map, min=1, max=SQLITE_MAX_ID_SIZE)


def id_converter_params(_converter: IdConverter) -> dict[str, Any]:
    return {"type": "integer", "minimum": 1, "maximum": SQLITE_MAX_ID_SIZE}
