from typing import Any

from flask import current_app
from flask.views import MethodView
from flask_smorest import Blueprint
from flask_smorest.error_handler import ErrorSchema
from flask_smorest.pagination import PaginationParameters
from flask_sqlalchemy.pagination import Pagination
from marshmallow import Schema
from marshmallow.fields import Enum, Integer, Nested, String
from sqlalchemy.exc import IntegrityError, NoResultFound

from auth import auth
from db import db

from ..models import Firewall, FirewallAction
from ..repositories import FirewallRepository
from ..use_cases import (
    CreateFirewall,
    CreateFirewallCommand,
    DeleteFirewall,
    DeleteFirewallCommand,
)
from .exceptions import (
    abort_already_exists,
    abort_not_found,
)
from .rules import FirewallRuleNetworkAddressSchema, FirewallRulePortSchema
from .shemas import BaseSchema, PageSchema
from .validations import not_just_whitespace

firewalls = Blueprint(
    "firewalls", __name__, url_prefix="/firewalls", description="Firewalls API"
)

from .filtering_policies import filtering_policies

firewalls.register_blueprint(filtering_policies)


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


class FirewallFilterSchema(Schema):
    name = String()


@firewalls.route("/")
class Firewalls(MethodView):
    @auth.login_required
    @firewalls.arguments(FirewallFilterSchema, location="query")
    @firewalls.response(200, PageSchema(FirewallSchema))
    @firewalls.paginate()
    def get(
        self,
        args: dict[str, Any],
        pagination_parameters: PaginationParameters,
    ) -> Pagination:
        """
        Fetch a paginated list of `Firewall` records
        """
        settings = current_app.config["SETTINGS"]

        repository = FirewallRepository(db)

        page = db.paginate(
            repository.filter(**args),
            page=pagination_parameters.page,
            per_page=pagination_parameters.page_size,
            max_per_page=settings.max_per_page,
        )

        pagination_parameters.item_count = page.total

        return page

    @auth.login_required
    @firewalls.arguments(FirewallSchema)
    @firewalls.response(201, FirewallSchema)
    @firewalls.alt_response(404, schema=ErrorSchema)
    @firewalls.alt_response(409, schema=ErrorSchema)
    def post(
        self,
        new_firewall: dict[str, Any],
    ) -> Firewall:
        """
        Create a new `Firewall` record
        """
        create_firewall = CreateFirewall(db)

        try:
            return create_firewall(CreateFirewallCommand(**new_firewall))
        except IntegrityError:
            abort_already_exists("firewall")


@firewalls.route("/<id:firewall_id>/")
class FirewallById(MethodView):
    @auth.login_required
    @firewalls.response(200, FirewallSchema)
    @firewalls.alt_response(404, schema=ErrorSchema)
    def get(self, firewall_id: int) -> Firewall:
        """
        Fetch a single `Firewall` record by its ID
        """
        repository = FirewallRepository(db)

        try:
            return repository.get(firewall_id)
        except NoResultFound:
            abort_not_found("firewall", id=firewall_id)

    @auth.login_required
    @firewalls.response(204, None)
    @firewalls.alt_response(404, schema=ErrorSchema)
    def delete(
        self,
        firewall_id: int,
    ) -> None:
        """
        Delete a `Firewall` record by its ID
        """
        delete_firewall = DeleteFirewall(FirewallRepository(db), db)

        try:
            delete_firewall(DeleteFirewallCommand(firewall_id))
        except NoResultFound:
            abort_not_found("firewall", id=firewall_id)
