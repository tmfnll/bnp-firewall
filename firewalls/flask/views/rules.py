from typing import Any

from flask import current_app
from flask.views import MethodView
from flask_smorest import Blueprint
from flask_smorest.error_handler import ErrorSchema
from flask_smorest.pagination import PaginationParameters
from flask_sqlalchemy.pagination import Pagination
from sqlalchemy.exc import IntegrityError, NoResultFound

from auth import auth
from db import db
from firewalls.flask.exceptions import abort_already_exists, abort_not_found
from firewalls.flask.links import links, operation
from firewalls.flask.schemas.base import (
    PageSchema,
)
from firewalls.flask.schemas.rule_schema import (
    FirewallRuleFilterSchema,
    FirewallRuleSchema,
)
from firewalls.models import (
    FirewallRule,
)
from firewalls.repositories import (
    NestedFilteringPolicyRepository,
    NestedFirewallRuleRepository,
)
from firewalls.use_cases import (
    CreateFirewallRule,
    CreateFirewallRuleCommand,
    CreateFirewallRuleNetworkAddressCommand,
    CreateFirewallRulePortCommand,
    DeleteFirewallRule,
    DeleteFirewallRuleCommand,
)

rules = Blueprint(
    "rules",
    __name__,
    url_prefix="<id:filtering_policy_id>/rules",
    description="Firewall Rules API",
)


@rules.route("/")
class FirewallRules(MethodView):
    @auth.login_required
    @rules.arguments(FirewallRuleFilterSchema, location="query")
    @rules.response(200, PageSchema(FirewallRuleSchema))
    @rules.paginate()
    def get(
        self,
        args: dict[str, Any],
        firewall_id: int,
        filtering_policy_id: int,
        pagination_parameters: PaginationParameters,
    ) -> Pagination:
        """
        Fetch a paginated list of `FirewallRule` records
        """
        settings = current_app.config["SETTINGS"]

        repository = NestedFirewallRuleRepository(
            firewall_id, filtering_policy_id, db
        )

        page = db.paginate(
            repository.filter(**args),
            page=pagination_parameters.page,
            per_page=pagination_parameters.page_size,
            max_per_page=settings.max_per_page,
        )

        pagination_parameters.item_count = page.total

        return page

    @auth.login_required
    @links(
        rules,
        201,
        "getCreatedRule",
        "getRuleById",
        {
            "rule_id": ("id",),
            "filtering_policy_id": ("filtering_policy", "id"),
            "firewall_id": ("filtering_policy", "firewall", "id"),
        },
    )
    @links(
        rules,
        201,
        "deleteCreatedRule",
        "deleteRuleById",
        {
            "rule_id": ("id",),
            "filtering_policy_id": ("filtering_policy", "id"),
            "firewall_id": ("filtering_policy", "firewall", "id"),
        },
    )
    @operation(rules, "createRule")
    @rules.arguments(FirewallRuleSchema)
    @rules.response(201, FirewallRuleSchema)
    @rules.alt_response(404, schema=ErrorSchema)
    @rules.alt_response(409, schema=ErrorSchema)
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
                    action=new_rule_data["action"],
                    sources=[
                        CreateFirewallRuleNetworkAddressCommand(**source)
                        for source in new_rule_data["sources"]
                    ],
                    destinations=[
                        CreateFirewallRuleNetworkAddressCommand(**source)
                        for source in new_rule_data["destinations"]
                    ],
                    ports=[
                        CreateFirewallRulePortCommand(**port)
                        for port in new_rule_data["ports"]
                    ],
                    filtering_policy_id=filtering_policy_id,
                )
            )
        except NoResultFound:
            abort_not_found(
                "filtering-policy",
                id=filtering_policy_id,
                firewall_id=firewall_id,
            )
        except IntegrityError:
            abort_already_exists("rule")

        return rule


@rules.route("/<id:rule_id>/")
class FirewallRuleById(MethodView):
    @auth.login_required
    @rules.response(200, FirewallRuleSchema)
    @rules.alt_response(404, schema=ErrorSchema)
    @operation(rules, "getRuleById")
    def get(
        self, firewall_id: int, filtering_policy_id: int, rule_id: int
    ) -> FirewallRule:
        """
        Fetch a single `FirewallRule` record by its ID
        """
        repository = NestedFirewallRuleRepository(
            firewall_id, filtering_policy_id, db
        )

        try:
            return repository.get(rule_id)
        except NoResultFound:
            abort_not_found(
                "rule",
                id=rule_id,
                filtering_policy_id=filtering_policy_id,
                firewall_id=firewall_id,
            )

    @auth.login_required
    @rules.response(204, None)
    @rules.alt_response(404, schema=ErrorSchema)
    @operation(rules, "deleteRuleById")
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
            abort_not_found(
                "rule",
                id=rule_id,
                filtering_policy_id=filtering_policy_id,
                firewall_id=firewall_id,
            )
