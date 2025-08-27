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

from ..models import Firewall, FirewallAction
from ..repositories import FirewallRepository
from ..use_cases import (
    CreateFirewall,
    CreateFirewallCommand,
    DeleteFirewall,
    DeleteFirewallCommand,
)
from .shemas import ListQueryArgSchema, strip_base_values

firewalls = Blueprint(
    "firewalls", __name__, url_prefix="/firewalls", description="Firewalls API"
)

from .filtering_policies import filtering_policies

firewalls.register_blueprint(filtering_policies)


class FirewallFirewallRuleSchema(Schema):
    id = Integer()
    action = Enum(FirewallAction)
    source_address_pattern = String()
    source_port = Integer()
    destination_address_pattern = String()
    destination_port = Integer()


class FirewallFilteringPolicySchema(Schema):
    id = Integer()
    name = String()

    default_action = Enum(FirewallAction)
    rules = Nested(FirewallFirewallRuleSchema, many=True)


class FirewallSchema(Schema):
    id = Integer(dump_only=True)
    name = String(required=True)

    filtering_policies = Nested(
        FirewallFilteringPolicySchema, dump_only=True, many=True
    )


class FirewallFilterSchema(ListQueryArgSchema):
    name = String()


@firewalls.route("/")
class Firewalls(MethodView):
    @auth.login_required
    @firewalls.arguments(FirewallFilterSchema, location="query")
    @firewalls.response(200, FirewallSchema(many=True))
    def get(
        self,
        args: dict[str, Any],
    ) -> Pagination:
        """
        Fetch a paginated list of `Firewall` records
        """
        settings = current_app.config["SETTINGS"]

        repository = FirewallRepository(db)

        return db.paginate(
            repository.filter(**strip_base_values(args)),
            page=args["page"],
            per_page=args["per_page"],
            max_per_page=settings.max_per_page,
        )

    @auth.login_required
    @firewalls.arguments(FirewallSchema)
    @firewalls.response(201, FirewallSchema)
    def post(
        self,
        new_firewall: dict[str, Any],
    ) -> Firewall:
        """
        Create a new `Firewall` record
        """
        create_firewall = CreateFirewall(db)

        return create_firewall(CreateFirewallCommand(**new_firewall))


@firewalls.route("/<int:firewall_id>/")
class FirewallById(MethodView):
    @auth.login_required
    @firewalls.response(200, FirewallSchema)
    def get(self, firewall_id: int) -> Firewall:
        """
        Fetch a single `Firewall` record by its ID
        """
        repository = FirewallRepository(db)

        return db.one_or_404(
            repository.select().where(Firewall.id == firewall_id)
        )

    @auth.login_required
    @firewalls.response(204, None)
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
            abort(404)
