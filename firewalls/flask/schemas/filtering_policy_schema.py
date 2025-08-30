from marshmallow import Schema
from marshmallow.fields import Enum, Integer, Nested, String

from ...models import FirewallAction
from ..validations import not_just_whitespace
from .base import BaseSchema
from .rule_schema import (
    FirewallRuleNetworkAddressSchema,
    FirewallRulePortSchema,
)


class FilteringPolicyFirewallSchema(BaseSchema):
    id = Integer()
    name = String()


class FilteringPolicyFirewallRuleSchema(BaseSchema):
    id = Integer()

    action = Enum(FirewallAction)

    sources = Nested(FirewallRuleNetworkAddressSchema, many=True)
    destinations = Nested(FirewallRuleNetworkAddressSchema, many=True)

    ports = Nested(FirewallRulePortSchema, many=True)


class FilteringPolicySchema(BaseSchema):
    id = Integer(dump_only=True)
    firewall = Nested(FilteringPolicyFirewallSchema, dump_only=True)
    rules = Nested(FilteringPolicyFirewallRuleSchema, dump_only=True, many=True)

    name = String(required=True, validate=not_just_whitespace())

    default_action = Enum(FirewallAction, required=True)


class FilteringPolicyFilterSchema(Schema):
    name = String()
    default_action = Enum(FirewallAction)
