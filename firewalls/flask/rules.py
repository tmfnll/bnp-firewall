from typing import Any

from flask import abort, current_app
from flask.views import MethodView
from flask_smorest import Blueprint
from flask_sqlalchemy.pagination import Pagination
from marshmallow import Schema
from marshmallow.fields import Enum, Integer, Nested, String
from sqlalchemy.exc import NoResultFound

from auth import auth
from db import db
from firewalls.flask.shemas import ListQueryArgSchema, strip_base_values
from firewalls.models import (
    FirewallAction,
    FirewallRule,
)
from firewalls.repositories import (
    NestedFilteringPolicyRepository,
    NestedFirewallRuleRepository,
)
from firewalls.use_cases import (
    CreateFirewallRule,
    CreateFirewallRuleCommand,
    DeleteFirewallRule,
    DeleteFirewallRuleCommand,
)

rules = Blueprint(
    "rules",
    __name__,
    url_prefix="<int:filtering_policy_id>/rules",
    description="Firewall Rules API",
)


class FirewallRuleFirewallSchema(Schema):
    id = Integer()
    name = String()


class FirewallRuleFilteringPolicySchema(Schema):
    id = Integer()
    name = String()
    default_action = Enum(FirewallAction)

    firewall = Nested(FirewallRuleFirewallSchema)


class FirewallRuleSchema(Schema):
    id = Integer(dump_only=True)
    filtering_policy_id = Integer(dump_only=True)

    action = Enum(FirewallAction, required=True)

    source_address_pattern = String(required=True)
    source_port = Integer(required=True)

    destination_address_pattern = String(required=True)
    destination_port = Integer(required=True)

    filtering_policy = Nested(FirewallRuleFilteringPolicySchema, dump_only=True)


class FirewallRuleFilterSchema(ListQueryArgSchema):
    action = Enum(FirewallAction)
    source_address_pattern = String()
    source_port = Integer()
    destination_address_pattern = String()
    destination_port = Integer()


@rules.route("/")
class FirewallRules(MethodView):
    @auth.login_required
    @rules.arguments(FirewallRuleFilterSchema, location="query")
    @rules.response(200, FirewallRuleSchema(many=True))
    def get(
        self,
        args: dict[str, Any],
        firewall_id: int,
        filtering_policy_id: int,
    ) -> Pagination:
        """
        Fetch a paginated list of `FirewallRule` records
        """
        settings = current_app.config["SETTINGS"]

        repository = NestedFirewallRuleRepository(
            firewall_id, filtering_policy_id, db
        )

        return db.paginate(
            repository.filter(**strip_base_values(args)),
            page=args["page"],
            per_page=args["per_page"],
            max_per_page=settings.max_per_page,
        )

    @auth.login_required
    @rules.arguments(FirewallRuleSchema)
    @rules.response(201, FirewallRuleSchema)
    def post(
        self,
        new_rule_data: dict[str, Any],
        firewall_id: int,
        filtering_policy_id: int,
    ) -> FirewallRule:
        """
        Create a new `FirewallRule` record
        """
        create_firewall_rule = CreateFirewallRule(
            NestedFilteringPolicyRepository(firewall_id, db), db
        )

        try:
            rule = create_firewall_rule(
                CreateFirewallRuleCommand(
                    **new_rule_data, filtering_policy_id=filtering_policy_id
                )
            )
        except NoResultFound:
            abort(404)

        return rule


@rules.route("/<int:rule_id>/")
class FirewallRuleById(MethodView):
    @auth.login_required
    @rules.response(200, FirewallRuleSchema)
    def get(
        self, firewall_id: int, filtering_policy_id: int, rule_id: int
    ) -> FirewallRule:
        """
        Fetch a single `FirewallRule` record by its ID
        """
        repository = NestedFirewallRuleRepository(
            firewall_id, filtering_policy_id, db
        )

        return db.one_or_404(
            repository.select().where(FirewallRule.id == rule_id)
        )

    @auth.login_required
    @rules.response(204, None)
    def delete(
        self,
        firewall_id: int,
        filtering_policy_id: int,
        rule_id: int,
    ) -> None:
        """
        Delete a `FirewallRule` record by its ID
        """
        delete_rule = DeleteFirewallRule(
            NestedFirewallRuleRepository(firewall_id, filtering_policy_id, db),
            db,
        )

        try:
            delete_rule(DeleteFirewallRuleCommand(id=rule_id))
        except NoResultFound:
            abort(404)
