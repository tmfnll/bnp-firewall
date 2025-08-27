from typing import Any

from marshmallow import Schema
from marshmallow.fields import Integer, String


class ListQueryArgSchema(Schema):
    page = Integer(load_default=1)
    per_page = Integer(load_default=20)
    sort_by = String(load_default="id")


def strip_base_values(args: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in args.items()
        if key not in ("page", "per_page", "sort_by")
    }
