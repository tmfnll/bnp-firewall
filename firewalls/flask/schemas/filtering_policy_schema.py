from marshmallow import Schema
from marshmallow.fields import Enum, Integer, Nested, String

from ...models import FirewallAction
from ...repositories import FilteringPolicyOrderBy
from ..validations import not_just_whitespace
from .base import BaseSchema, IpAddressField, OrderByEnum, QueryParametersSchema
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

    priority = Integer()

    sources = Nested(FirewallRuleNetworkAddressSchema, many=True)
    destinations = Nested(FirewallRuleNetworkAddressSchema, many=True)

    ports = Nested(FirewallRulePortSchema, many=True)


class FilteringPolicySchema(BaseSchema):
    id = Integer(dump_only=True)
    firewall = Nested(FilteringPolicyFirewallSchema, dump_only=True)
    rules = Nested(FilteringPolicyFirewallRuleSchema, dump_only=True, many=True)

    name = String(required=True, validate=not_just_whitespace())

    default_action = Enum(FirewallAction, required=True)


class FilteringPolicyFilterSchema(QueryParametersSchema):
    name = String()
    default_action = Enum(FirewallAction)
    order_by = OrderByEnum(FilteringPolicyOrderBy)


class PacketSchema(BaseSchema):
    source_address = IpAddressField(required=True)
    source_port = Integer(required=True)

    destination_address = IpAddressField(required=True)
    destination_port = Integer(required=True)


class InspectionSchema(Schema):
    action = Enum(FirewallAction)
    active_rule = Nested(FilteringPolicyFirewallRuleSchema, allow_none=True)
