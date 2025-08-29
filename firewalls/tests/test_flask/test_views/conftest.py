from datetime import datetime

import pytest

from firewalls.models import (
    FilteringPolicy,
    Firewall,
    FirewallAction,
    FirewallRule,
)
from firewalls.tests.factories import (
    FilteringPolicyFactory,
    FirewallFactory,
    FirewallRuleFactory,
)


@pytest.fixture
def firewall_deleted_at() -> None:
    return None


@pytest.fixture
def firewall(firewall_deleted_at: datetime) -> Firewall:
    return FirewallFactory.create(
        filtering_policies=[], deleted_at=firewall_deleted_at
    )


@pytest.fixture
def another_firewall() -> Firewall:
    return FirewallFactory.create(filtering_policies=[])


@pytest.fixture
def filtering_policy_deleted_at() -> None:
    return None


@pytest.fixture
def filtering_policy(
    firewall: Firewall, filtering_policy_deleted_at: datetime
) -> FilteringPolicy:
    return FilteringPolicyFactory.create(
        rules=[],
        firewall=firewall,
        deleted_at=filtering_policy_deleted_at,
        default_action=FirewallAction.ALLOW,
    )


@pytest.fixture
def another_filtering_policy(firewall: Firewall) -> FilteringPolicy:
    return FilteringPolicyFactory.create(
        rules=[],
        firewall=firewall,
    )


@pytest.fixture
def rule_deleted_at() -> None:
    return None


@pytest.fixture
def rule(
    filtering_policy: FilteringPolicy, rule_deleted_at: datetime
) -> FirewallRule:
    return FirewallRuleFactory.create(
        filtering_policy=filtering_policy, deleted_at=rule_deleted_at
    )


@pytest.fixture
def another_rule(filtering_policy: FilteringPolicy) -> FirewallRule:
    return FirewallRuleFactory.create(filtering_policy=filtering_policy)
