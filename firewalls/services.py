from typing import Sequence

from db import Base
from firewalls.models import (
    FilteringPolicy,
    FirewallAction,
    FirewallRule,
    FirewallRuleDestination,
    FirewallRulePort,
    FirewallRuleSource,
    ValidationError,
)


def _raise_if_empty(
    relation: Sequence[Base],
    name: str,
) -> None:
    if not relation:
        raise ValidationError(f"{name} cannot be empty")


def build_firewall_rule(
    filtering_policy: FilteringPolicy,
    action: FirewallAction,
    priority: int,
    sources: list[FirewallRuleSource],
    destinations: list[FirewallRuleDestination],
    ports: list[FirewallRulePort],
) -> FirewallRule:
    _raise_if_empty(sources, "sources")
    _raise_if_empty(destinations, "destinations")
    _raise_if_empty(ports, "ports")

    firewall_rule = FirewallRule(
        filtering_policy=filtering_policy,
        action=action,
        priority=priority,
        sources=sources,
        destinations=destinations,
        ports=ports,
    ).set_hashes()

    return firewall_rule
