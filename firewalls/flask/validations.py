from typing import ClassVar, overload

from marshmallow import ValidationError
from marshmallow.validate import Range, Regexp

from firewalls import models
from firewalls.models import (
    ADDRESS_REGEX,
    VALID_TCP_PORT_RANGE,
    validate_ip_address_or_subnet_cidr,
)


def not_just_whitespace():
    pattern = r"\A(?!\s+$).+\Z"

    return Regexp(pattern, error="Cannot be blank")


class IsValidIPAddressOrSubnetCIDR(Regexp):
    pattern: ClassVar[str] = rf"^{ADDRESS_REGEX}$"

    def __init__(self):
        super().__init__(
            self.pattern,
            error="{input} is not a valid IP address or subnet CIDR",
        )

    @overload
    def __call__(self, value: str) -> str: ...

    @overload
    def __call__(self, value: bytes) -> bytes: ...

    def __call__(self, value: str | bytes) -> str | bytes:
        if isinstance(value, bytes):  # pragma: no cover
            value = value.decode("utf-8")

        try:
            validate_ip_address_or_subnet_cidr(value)
        except models.ValidationError:
            raise ValidationError(self._format_error(value))

        return value


def is_valid_tcp_port() -> Range:
    return Range(
        *VALID_TCP_PORT_RANGE, error="{input} is not a valid TCP port number"
    )
