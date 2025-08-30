from typing import Any

from flask import current_app
from flask.views import MethodView
from flask_smorest import Blueprint
from flask_smorest.error_handler import ErrorSchema
from flask_smorest.pagination import PaginationParameters
from flask_sqlalchemy.pagination import Pagination
from sqlalchemy.exc import IntegrityError, NoResultFound

from auth import require_login
from db import db
from firewalls.flask.exceptions import (
    abort_already_exists,
    abort_not_found,
)
from firewalls.flask.links import links, operation
from firewalls.flask.schemas.base import PageSchema
from firewalls.models import Firewall
from firewalls.repositories import FirewallRepository
from firewalls.use_cases import (
    CreateFirewall,
    CreateFirewallCommand,
    DeleteFirewall,
    DeleteFirewallCommand,
)

from ..schemas import FirewallFilterSchema, FirewallSchema

firewalls = Blueprint(
    "firewalls", __name__, url_prefix="/firewalls", description="Firewalls API"
)

from .filtering_policies import filtering_policies

firewalls.register_blueprint(filtering_policies)

firewalls.before_request(require_login)


@firewalls.route("/")
class Firewalls(MethodView):

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

    @links(
        firewalls,
        201,
        "getCreatedFirewall",
        "getFirewallById",
        {"firewall_id": ("id",)},
    )
    @links(
        firewalls,
        201,
        "deleteCreatedFirewall",
        "deleteFirewallById",
        {"firewall_id": ("id",)},
    )
    @operation(firewalls, "createFirewall")
    @firewalls.arguments(FirewallSchema)
    @firewalls.response(201, FirewallSchema)
    @firewalls.alt_response(404, schema=ErrorSchema)
    @firewalls.alt_response(422, schema=ErrorSchema)
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

    @firewalls.response(200, FirewallSchema)
    @firewalls.alt_response(404, schema=ErrorSchema)
    @operation(firewalls, "getFirewallById")
    def get(self, firewall_id: int) -> Firewall:
        """
        Fetch a single `Firewall` record by its ID
        """
        repository = FirewallRepository(db)

        try:
            return repository.get(firewall_id)
        except NoResultFound:
            abort_not_found("firewall", id=firewall_id)

    @firewalls.response(204, None)
    @firewalls.alt_response(404, schema=ErrorSchema)
    @operation(firewalls, "deleteFirewallById")
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
