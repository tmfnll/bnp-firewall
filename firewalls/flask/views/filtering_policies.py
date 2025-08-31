from typing import Any

from flask import current_app
from flask.views import MethodView
from flask_smorest import Blueprint
from flask_smorest.error_handler import ErrorSchema
from flask_smorest.pagination import PaginationParameters
from flask_sqlalchemy.pagination import Pagination
from sqlalchemy.exc import IntegrityError, NoResultFound

from auth import UserRole, authorise
from db import db
from firewalls.flask.exceptions import abort_integrity_error, abort_not_found
from firewalls.flask.links import links, operation
from firewalls.flask.schemas.base import PageSchema
from firewalls.models import FilteringPolicy
from firewalls.repositories import (
    FirewallRepository,
    NestedFilteringPolicyRepository,
)
from firewalls.use_cases import (
    CreateFilteringPolicy,
    CreateFilteringPolicyCommand,
    DeleteFilteringPolicy,
    DeleteFilteringPolicyCommand,
)

from ..schemas import FilteringPolicyFilterSchema, FilteringPolicySchema
from .rules import (
    rules,
)

filtering_policies = Blueprint(
    "filtering_policies",
    __name__,
    url_prefix="/<id:firewall_id>/filtering-policies",
    description="Filtering Policies API",
)


filtering_policies.register_blueprint(rules)


@filtering_policies.route("/")
class FilteringPolicies(MethodView):

    @authorise(UserRole.VIEWER)
    @filtering_policies.arguments(FilteringPolicyFilterSchema, location="query")
    @filtering_policies.response(200, PageSchema(FilteringPolicySchema))
    @filtering_policies.paginate()
    def get(
        self,
        args: dict[str, Any],
        firewall_id: int,
        pagination_parameters: PaginationParameters,
    ) -> Pagination:
        """
        Fetch a paginated list of `FilteringPolicy` records
        """
        settings = current_app.config["SETTINGS"]

        repository = NestedFilteringPolicyRepository(firewall_id, db)

        page = db.paginate(
            repository.filter(**args),
            page=pagination_parameters.page,
            per_page=pagination_parameters.page_size,
            max_per_page=settings.max_per_page,
        )

        pagination_parameters.item_count = page.total

        return page

    @authorise(UserRole.EDITOR)
    @links(
        filtering_policies,
        201,
        "getCreatedFilteringPolicy",
        "getFilteringPolicyById",
        {
            "filtering_policy_id": ("id",),
            "firewall_id": ("firewall", "id"),
        },
    )
    @links(
        filtering_policies,
        201,
        "deleteCreatedFilteringPolicy",
        "deleteFilteringPolicyById",
        {
            "filtering_policy_id": ("id",),
            "firewall_id": ("firewall", "id"),
        },
    )
    @operation(filtering_policies, "createFilteringPolicy")
    @filtering_policies.arguments(FilteringPolicySchema)
    @filtering_policies.response(201, FilteringPolicySchema)
    @filtering_policies.alt_response(404, schema=ErrorSchema)
    @filtering_policies.alt_response(409, schema=ErrorSchema)
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
            abort_not_found("firewall", id=firewall_id)
        except IntegrityError as exc:
            abort_integrity_error("filtering-policy", exc)

        return filtering_policy


@filtering_policies.route("/<id:filtering_policy_id>/")
class FilteringPolicyById(MethodView):

    @authorise(UserRole.VIEWER)
    @filtering_policies.response(200, FilteringPolicySchema)
    @filtering_policies.alt_response(404, schema=ErrorSchema)
    @operation(filtering_policies, "getFilteringPolicyById")
    def get(
        self, firewall_id: int, filtering_policy_id: int
    ) -> FilteringPolicy:
        """
        Fetch a single `FilteringPolicy` record by its ID
        """
        repository = NestedFilteringPolicyRepository(firewall_id, db)

        try:
            return repository.get(filtering_policy_id)
        except NoResultFound:
            abort_not_found(
                "filtering-policy",
                id=filtering_policy_id,
                firewall_id=firewall_id,
            )

    @authorise(UserRole.EDITOR)
    @filtering_policies.response(204, None)
    @filtering_policies.alt_response(404, schema=ErrorSchema)
    @operation(filtering_policies, "deleteFilteringPolicyById")
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
            abort_not_found(
                "filtering-policy",
                id=filtering_policy_id,
                firewall_id=firewall_id,
            )
