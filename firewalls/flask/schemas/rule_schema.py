from marshmallow.fields import Enum, Integer, Nested, String
from marshmallow.validate import Length

from ...models import FirewallAction
from ...repositories import FirewallRuleOrderBy
from .base import (
    BaseSchema,
    IpOrSubnetCidrField,
    OrderByEnum,
    PortField,
    QueryParametersSchema,
)


class FirewallRuleFirewallSchema(BaseSchema):
    id = Integer()
    name = String()


class FirewallRuleFilteringPolicySchema(BaseSchema):
    id = Integer()
    name = String()
    default_action = Enum(FirewallAction)

    firewall = Nested(FirewallRuleFirewallSchema)


class FirewallRuleNetworkAddressSchema(BaseSchema):
    address = IpOrSubnetCidrField(required=True)
    port = PortField(required=True)


class FirewallRulePortSchema(BaseSchema):
    number = PortField(required=True)


class FirewallRuleSchema(BaseSchema):
    id = Integer(dump_only=True)
    action = Enum(FirewallAction, required=True)

    sources = Nested(
        FirewallRuleNetworkAddressSchema,
        many=True,
        required=True,
        validate=Length(1),
    )
    destinations = Nested(
        FirewallRuleNetworkAddressSchema,
        many=True,
        required=True,
        validate=Length(1),
    )

    ports = Nested(
        FirewallRulePortSchema, many=True, required=True, validate=Length(1)
    )

    filtering_policy = Nested(FirewallRuleFilteringPolicySchema, dump_only=True)


class FirewallRuleFilterSchema(QueryParametersSchema):
    action = Enum(FirewallAction)
    source_address = IpOrSubnetCidrField(example=None)
    source_port = PortField(example=None)
    destination_address = IpOrSubnetCidrField(example=None)
    destination_port = PortField(example=None)
    port = PortField(example=None)
    order_by = OrderByEnum(FirewallRuleOrderBy)
