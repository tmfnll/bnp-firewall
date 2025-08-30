from enum import StrEnum
from typing import Any, cast

from marshmallow import Schema
from marshmallow.fields import Enum, Integer, Nested, String

from firewalls.flask.validations import (
    IsValidIPAddressOrSubnetCIDR,
    is_valid_tcp_port,
)


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


def ip_or_subnet_cidr_field(
    *args: Any,
    example: str | None = "92.168.1.0/24",
    description: str | None = "An IP address or a subnet in CIDR notation",
    **kwargs: Any,
) -> String:
    metadata: dict[str, Any] = {}

    if example is not None:
        metadata["example"] = example

    if description is not None:
        metadata["description"] = description

    return String(
        *args,
        validate=IsValidIPAddressOrSubnetCIDR(),
        metadata=metadata,
        **kwargs,
    )


IpOrSubnetCidrField = ip_or_subnet_cidr_field


def port_field(
    *args: Any,
    example: int | None = 443,
    description: str | None = "A TCP port number between 0 and 65535",
    **kwargs: Any,
) -> Integer:
    metadata: dict[str, Any] = {}

    if example is not None:
        metadata["example"] = example

    if description is not None:
        metadata["description"] = description

    return Integer(
        *args,
        validate=is_valid_tcp_port(),
        metadata=metadata,
        **kwargs,
    )


PortField = port_field


class QueryParametersSchema(Schema):
    pass


def order_by_enum(
    enum: type[StrEnum],
    *args: Any,
    **kwargs: Any,
) -> Enum:
    return Enum(
        enum,
        by_value=True,
        *args,
        load_default=getattr(enum, "id"),
        **kwargs,
    )


OrderByEnum = order_by_enum
