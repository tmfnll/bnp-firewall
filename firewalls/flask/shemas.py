from typing import cast

from marshmallow import Schema
from marshmallow.fields import Integer, Nested


class BaseSchema(Schema):
    class Meta:
        ordered = True
        unknown = "exclude"  # This allows the API to be forward compatible


def page_schema(schema_type: type[Schema]) -> type[Schema]:
    schema_prefix = schema_type.__name__

    if schema_prefix.endswith("Schema"):
        schema_prefix = schema_prefix[: -len("Schema")]

    return cast(
        type[Schema],
        type(
            f"{schema_prefix}PageSchema",
            (Schema,),
            {
                "items": Nested(schema_type, many=True),
                "total": Integer(),
                "page": Integer(),
                "per_page": Integer(),
            },
        ),
    )


PageSchema = page_schema
