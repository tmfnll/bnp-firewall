from typing import TypedDict

import pytest

from firewalls.models import (
    FilteringPolicy,
    FirewallAction,
    FirewallRuleDestination,
    FirewallRulePort,
    FirewallRuleSource,
    ValidationError,
)
from firewalls.services import build_firewall_rule
from firewalls.tests.factories import (
    FilteringPolicyFactory,
    FirewallRuleDestinationFactory,
    FirewallRulePortFactory,
    FirewallRuleSourceFactory,
)


class RelationKwargs(TypedDict, total=False):
    sources: list[FirewallRuleSource]
    destinations: list[FirewallRuleDestination]
    ports: list[FirewallRulePort]


class TestBuildFirewallRule:
    @pytest.fixture
    def firewall_rule_sources(self) -> list[FirewallRuleSource]:
        return FirewallRuleSourceFactory.build_batch(2, firewall_rule=None)

    @pytest.fixture
    def firewall_rule_destinations(self) -> list[FirewallRuleDestination]:
        return FirewallRuleDestinationFactory.build_batch(2, firewall_rule=None)

    @pytest.fixture
    def firewall_rule_ports(self) -> list[FirewallRulePort]:
        return FirewallRulePortFactory.build_batch(2, firewall_rule=None)

    @pytest.fixture
    def action(self) -> FirewallAction:
        return FirewallAction.ALLOW

    @pytest.fixture
    def filtering_policy(self) -> FilteringPolicy:
        return FilteringPolicyFactory.create(rules=[])

    def test_it_builds_a_firewall_rule(
        self,
        action: FirewallAction,
        firewall_rule_sources: list[FirewallRuleSource],
        firewall_rule_destinations: list[FirewallRuleDestination],
        firewall_rule_ports: list[FirewallRulePort],
        filtering_policy: FilteringPolicy,
    ) -> None:
        rule = build_firewall_rule(
            action=action,
            sources=firewall_rule_sources,
            destinations=firewall_rule_destinations,
            ports=firewall_rule_ports,
            filtering_policy=filtering_policy,
        )
        assert rule.action == action
        assert rule.filtering_policy == filtering_policy
        assert rule.sources == firewall_rule_sources
        assert rule.destinations == firewall_rule_destinations
        assert rule.ports == firewall_rule_ports

        assert rule.source_hash == hash(
            frozenset(
                hash((source.address, source.port))
                for source in firewall_rule_sources
            )
        )
        assert rule.destination_hash == hash(
            frozenset(
                hash((destination.address, destination.port))
                for destination in firewall_rule_destinations
            )
        )
        assert rule.port_hash == hash(
            frozenset(hash(port.number) for port in firewall_rule_ports)
        )

    def test_rules_with_the_same_relations_have_matching_hashes(
        self,
        action: FirewallAction,
        firewall_rule_sources: list[FirewallRuleSource],
        firewall_rule_destinations: list[FirewallRuleDestination],
        firewall_rule_ports: list[FirewallRulePort],
        filtering_policy: FilteringPolicy,
    ) -> None:
        rule = build_firewall_rule(
            action=action,
            sources=firewall_rule_sources,
            destinations=firewall_rule_destinations,
            ports=firewall_rule_ports,
            filtering_policy=filtering_policy,
        )

        another_rule = build_firewall_rule(
            action=action,
            sources=firewall_rule_sources,
            destinations=firewall_rule_destinations,
            ports=firewall_rule_ports,
            filtering_policy=filtering_policy,
        )

        assert rule.source_hash == another_rule.source_hash
        assert rule.destination_hash == another_rule.destination_hash
        assert rule.port_hash == another_rule.port_hash

    @pytest.mark.parametrize(
        ("relation",),
        (
            ("sources",),
            ("destinations",),
            ("ports",),
        ),
    )
    def test_a_validation_error_is_raised_when_validations_are_missing(
        self,
        action: FirewallAction,
        relation: str,
        firewall_rule_sources: list[FirewallRuleSource],
        firewall_rule_destinations: list[FirewallRuleDestination],
        firewall_rule_ports: list[FirewallRulePort],
        filtering_policy: FilteringPolicy,
    ) -> None:
        relations: RelationKwargs = {
            "sources": firewall_rule_sources,
            "destinations": firewall_rule_destinations,
            "ports": firewall_rule_ports,
        }

        relations[relation] = []  # type: ignore[literal-required]

        with pytest.raises(ValidationError) as exc:
            build_firewall_rule(
                action=action,
                sources=relations["sources"],
                destinations=relations["destinations"],
                ports=relations["ports"],
                filtering_policy=filtering_policy,
            )

        assert str(exc.value) == f"{relation} cannot be empty"
