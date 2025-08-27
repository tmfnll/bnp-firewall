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

from ..models import FilteringPolicy, FirewallAction
from ..repositories import FirewallRepository, NestedFilteringPolicyRepository
from ..use_cases import (
    CreateFilteringPolicy,
    CreateFilteringPolicyCommand,
    DeleteFilteringPolicy,
    DeleteFilteringPolicyCommand,
)
from .rules import rules
from .shemas import ListQueryArgSchema, strip_base_values

filtering_policies = Blueprint(
    "filtering_policies",
    __name__,
    url_prefix="/<int:firewall_id>/filtering-policies",
    description="Filtering Policies API",
)


filtering_policies.register_blueprint(rules)


class FilteringPolicyFirewallSchema(Schema):
    id = Integer()
    name = String()


class FilteringPolicyFirewallRuleSchema(Schema):
    id = Integer()

    action = Enum(FirewallAction)

    source_address_pattern = String()
    source_port = Integer()

    destination_address_pattern = String()
    destination_port = Integer()


class FilteringPolicySchema(Schema):
    id = Integer(dump_only=True)
    firewall = Nested(FilteringPolicyFirewallSchema, dump_only=True)
    rules = Nested(FilteringPolicyFirewallRuleSchema, dump_only=True, many=True)

    name = String(required=True)

    default_action = Enum(FirewallAction, required=True)


class FilteringPolicyFilterSchema(ListQueryArgSchema):
    name = String()
    default_action = Enum(FirewallAction)


@filtering_policies.route("/")
class FilteringPolicies(MethodView):
    @auth.login_required
    @filtering_policies.arguments(FilteringPolicyFilterSchema, location="query")
    @filtering_policies.response(200, FilteringPolicySchema(many=True))
    def get(
        self,
        args: dict[str, Any],
        firewall_id: int,
    ) -> Pagination:
        """
        Fetch a paginated list of `FilteringPolicy` records
        """
        settings = current_app.config["SETTINGS"]

        repository = NestedFilteringPolicyRepository(firewall_id, db)

        return db.paginate(
            repository.filter(**strip_base_values(args)),
            page=args["page"],
            per_page=args["per_page"],
            max_per_page=settings.max_per_page,
        )

    @auth.login_required
    @filtering_policies.arguments(FilteringPolicySchema)
    @filtering_policies.response(201, FilteringPolicySchema)
    def post(
        self,
        new_filtering_policy: dict[str, Any],
        firewall_id: int,
    ) -> FilteringPolicy:
        """
        Create a new `FilteringPolicy` record
        """
        create_filtering_policy = CreateFilteringPolicy(
            FirewallRepository(db),
            db,
        )

        try:
            filtering_policy = create_filtering_policy(
                CreateFilteringPolicyCommand(
                    firewall_id=firewall_id,
                    **new_filtering_policy,
                )
            )
        except NoResultFound:
            abort(404)

        return filtering_policy


@filtering_policies.route("/<int:filtering_policy_id>/")
class FilteringPolicyById(MethodView):
    @auth.login_required
    @filtering_policies.response(200, FilteringPolicySchema)
    def get(
        self, firewall_id: int, filtering_policy_id: int
    ) -> FilteringPolicy:
        """
        Fetch a single `FilteringPolicy` record by its ID
        """
        repository = NestedFilteringPolicyRepository(firewall_id, db)

        return db.one_or_404(
            repository.select().where(FilteringPolicy.id == filtering_policy_id)
        )

    @auth.login_required
    @filtering_policies.response(204, None)
    def delete(
        self,
        firewall_id: int,
        filtering_policy_id: int,
    ) -> None:
        """
        Delete a `FilteringPolicy` record by its ID
        """
        delete_filtering_policy = DeleteFilteringPolicy(
            NestedFilteringPolicyRepository(firewall_id, db),
            db,
        )

        try:
            delete_filtering_policy(
                DeleteFilteringPolicyCommand(filtering_policy_id)
            )
        except NoResultFound:
            abort(404)
