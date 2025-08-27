from typing import Any

from sqlalchemy import Select
from sqlalchemy.orm import joinedload, selectinload

from firewalls.models import FilteringPolicy, Firewall, FirewallRule
from repository import Repository


class FirewallRepository(Repository):
    model_type = Firewall

    default_options = [
        selectinload(Firewall.filtering_policies).selectinload(
            FilteringPolicy.rules
        )
    ]


class NestedFilteringPolicyRepository(Repository):
    def __init__(self, firewall_id: int, *args: Any, **kwargs: Any):
        super().__init__(*args, **kwargs)

        self.firewall_id = firewall_id

    default_options = [
        joinedload(FilteringPolicy.firewall),
        selectinload(FilteringPolicy.rules),
    ]

    model_type = FilteringPolicy

    def select_all(self) -> Select:
        select_ = (
            super()
            .select_all()
            .join(Firewall, Firewall.id == FilteringPolicy.firewall_id)
            .where(
                Firewall.id == self.firewall_id,
                Firewall.deleted_at.is_(None),
            )
        )

        return select_


class NestedFirewallRuleRepository(Repository):
    def __init__(
        self,
        firewall_id: int,
        filtering_policy_id: int,
        *args: Any,
        **kwargs: Any
    ):
        super().__init__(*args, **kwargs)

        self.firewall_id = firewall_id
        self.filtering_policy_id = filtering_policy_id

    model_type = FirewallRule

    default_options = [
        joinedload(FirewallRule.filtering_policy).joinedload(
            FilteringPolicy.firewall
        ),
    ]

    def select_all(self) -> Select:
        return (
            super()
            .select_all()
            .join(
                FilteringPolicy,
                FilteringPolicy.id == FirewallRule.filtering_policy_id,
            )
            .join(
                Firewall,
                Firewall.id == FilteringPolicy.firewall_id,
            )
            .where(
                Firewall.id == self.firewall_id,
                Firewall.deleted_at.is_(None),
            )
            .where(
                FilteringPolicy.id == self.filtering_policy_id,
                FilteringPolicy.deleted_at.is_(None),
            )
        )
