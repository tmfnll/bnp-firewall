from marshmallow.fields import Enum, Integer, Nested, String

from ...models import FirewallAction
from ...repositories import FirewallOrderBy
from ..validations import not_just_whitespace
from .base import BaseSchema, OrderByEnum, QueryParametersSchema
from .rule_schema import (
    FirewallRuleNetworkAddressSchema,
    FirewallRulePortSchema,
)


class FirewallFirewallRuleSchema(BaseSchema):
    id = Integer()

    action = Enum(FirewallAction)

    sources = Nested(FirewallRuleNetworkAddressSchema, many=True)
    destinations = Nested(FirewallRuleNetworkAddressSchema, many=True)

    ports = Nested(FirewallRulePortSchema, many=True)


class FirewallFilteringPolicySchema(BaseSchema):
    id = Integer()
    name = String()

    default_action = Enum(FirewallAction)
    rules = Nested(FirewallFirewallRuleSchema, many=True)


class FirewallSchema(BaseSchema):
    id = Integer(dump_only=True)
    name = String(required=True, validate=not_just_whitespace())

    filtering_policies = Nested(
        FirewallFilteringPolicySchema, dump_only=True, many=True
    )


class FirewallFilterSchema(QueryParametersSchema):
    name = String()
    order_by = OrderByEnum(FirewallOrderBy)
