from datetime import datetime, timezone

import pytest

from firewalls.models import (
    FilteringPolicy,
    FirewallAction,
    FirewallRule,
    Inspection,
    Packet,
    ValidationError,
)
from firewalls.tests.factories import (
    FilteringPolicyFactory,
    FirewallFactory,
    FirewallRuleDestinationFactory,
    FirewallRuleFactory,
    FirewallRulePortFactory,
    FirewallRuleSourceFactory,
)


@pytest.fixture
def packet(
    source_address: str,
    source_port: int,
    destination_address: str,
    destination_port: int,
) -> Packet:
    return Packet(
        source_address=source_address,
        source_port=source_port,
        destination_address=destination_address,
        destination_port=destination_port,
    )


class TestFirewallRule:
    @pytest.fixture
    def rule_deleted_at(self) -> None:
        return None

    @pytest.fixture
    def rule(self, rule_deleted_at: datetime | None) -> FirewallRule:
        rule_ = FirewallRuleFactory.build(
            sources=[],
            destinations=[],
            deleted_at=rule_deleted_at,
        )

        rule_.sources.append(
            FirewallRuleSourceFactory.build(
                address="100.100.100.0/24",
                port=8080,
            ),
        )

        rule_.destinations.append(
            FirewallRuleDestinationFactory.build(
                address="99.99.99.99",
                port=80,
            )
        )

        return rule_

    @pytest.mark.parametrize(
        (
            "source_address",
            "source_port",
            "destination_address",
            "destination_port",
            "action_expected",
        ),
        (
            (
                "100.100.100.1",
                8080,
                "99.99.99.99",
                80,
                True,
            ),
            (
                "100.100.100.10",
                8080,
                "99.99.99.99",
                80,
                True,
            ),
            (
                "100.100.100.100",
                8080,
                "99.99.99.99",
                80,
                True,
            ),
            (
                "166.100.9.100",  # Mismatched source address
                8080,
                "99.99.99.99",
                80,
                False,
            ),
            (
                "100.100.100.100",
                8081,  # Mismatched source port
                "99.99.99.99",
                80,
                False,
            ),
            (
                "100.100.100.100",
                8080,
                "36.52.12.87",  # Mismatched destination address
                80,
                False,
            ),
            (
                "100.100.100.100",
                8080,
                "99.99.99.99",
                81,  # Mismatched destination port
                False,
            ),
        ),
    )
    def test_inspect(
        self, rule: FirewallRule, packet: Packet, action_expected: bool
    ) -> None:
        action = rule.inspect(packet)

        if action_expected:
            assert action == rule.action
        else:
            assert action is None

    class TestWhenDeletedAtIsSet:
        @pytest.fixture
        def rule_deleted_at(self) -> datetime:
            return datetime.now(tz=timezone.utc)

        def test_is_deleted_is_true(self, rule: FirewallRule) -> None:
            assert rule.is_deleted


class TestFilteringPolicy:
    @pytest.fixture
    def filtering_policy(self) -> FilteringPolicy:
        return FilteringPolicyFactory.create(rules=[])

    @pytest.fixture
    def rules(self, filtering_policy: FilteringPolicy) -> list[FirewallRule]:
        return [
            FirewallRuleFactory.create(
                filtering_policy=filtering_policy,
                sources__address="100.100.100.0/24",
                sources__port=8080,
                destinations__address="99.99.99.99",
                destinations__port=80,
                action=FirewallAction.ALLOW,
            ),
            FirewallRuleFactory.create(
                filtering_policy=filtering_policy,
                sources__address="200.200.200.0/24",
                sources__port=8080,
                destinations__address="77.77.77.77",
                destinations__port=80,
                action=FirewallAction.DENY,
            ),
        ]

    @pytest.mark.parametrize(
        (
            "source_address",
            "source_port",
            "destination_address",
            "destination_port",
            "rule_index",
        ),
        (
            (
                "100.100.100.1",
                8080,
                "99.99.99.99",
                80,
                0,
            ),
            (
                "200.200.200.200",
                8080,
                "77.77.77.77",
                80,
                1,
            ),
            (
                "255.255.255.255",  # Mismatched source address
                8080,
                "77.77.77.77",
                80,
                None,
            ),
        ),
    )
    def test_inspect(
        self,
        filtering_policy: FilteringPolicy,
        rules: list[FirewallRule],
        packet: Packet,
        rule_index: int | None,
    ) -> None:
        inspection = filtering_policy.inspect(packet)

        if rule_index is not None:
            rule = rules[rule_index]

            assert inspection == Inspection(rule.action, rule)
        else:
            assert inspection == Inspection(
                filtering_policy.default_action, None
            )

    class TestPriority:
        @pytest.fixture
        def rules(
            self, filtering_policy: FilteringPolicy, priorities: tuple[int, int]
        ) -> list[FirewallRule]:
            return [
                FirewallRuleFactory.create(
                    filtering_policy=filtering_policy,
                    sources__address="100.100.100.0/24",
                    sources__port=8080,
                    destinations__address="99.99.99.99",
                    destinations__port=80,
                    action=FirewallAction.ALLOW,
                    priority=priorities[0],
                ),
                FirewallRuleFactory.create(
                    filtering_policy=filtering_policy,
                    sources__address="100.100.100.0/24",
                    sources__port=8080,
                    destinations__address="99.99.99.99",
                    destinations__port=80,
                    action=FirewallAction.DENY,
                    priority=priorities[1],
                ),
            ]

        @pytest.fixture
        def packet(self) -> Packet:
            return Packet(
                source_address="100.100.100.100",
                source_port=8080,
                destination_address="99.99.99.99",
                destination_port=80,
            )

        @pytest.mark.parametrize(
            ("priorities", "rule_index"),
            (
                ((1, 2), 0),
                ((2, 1), 1),
                ((1, 1), 0),
                ((-1, 1), 0),
                ((1, -1), 1),
            ),
        )
        def test_prioritised_rules(
            self,
            filtering_policy: FilteringPolicy,
            packet: Packet,
            rules: list[FirewallRule],
            rule_index: int,
        ) -> None:
            rule = rules[rule_index]

            assert filtering_policy.inspect(packet) == Inspection(
                rule.action, rule
            )

    @pytest.mark.parametrize(
        ("name", "is_valid"),
        (("foo", True), ("   foo  ", True), ("", False), ("    ", False)),
    )
    def test_name_validation(self, name: str, is_valid: bool) -> None:
        if is_valid:
            FilteringPolicyFactory.build(name=name)
        else:
            with pytest.raises(
                ValidationError, match="Name cannot be empty or whitespace"
            ):
                FilteringPolicyFactory.build(name=name)


class TestFirewall:
    @pytest.mark.parametrize(
        ("name", "is_valid"),
        (("foo", True), ("   foo  ", True), ("", False), ("    ", False)),
    )
    def test_name_validation(self, name: str, is_valid: bool) -> None:
        if is_valid:
            FirewallFactory.build(name=name)
        else:
            with pytest.raises(
                ValidationError, match="Name cannot be empty or whitespace"
            ):
                FirewallFactory.build(name=name)


class TestFirewallRuleSource:
    @pytest.mark.parametrize(
        ("address", "is_valid"),
        (
            ("1.1.1.1", True),
            ("1.1.1.0/24", True),
            ("256.1.1.1", False),
            ("", False),
            ("   ", False),
            ("invalid", False),
            ("1.1.1.00/24", False),
            ("1.1.1.1/33", False),
            ("1.1.1.1/32", True),
            ("1.1.1.0/16", False),
            ("1.1.0.0/16", True),
        ),
    )
    def test_address_validation(self, address: str, is_valid: bool) -> None:
        if is_valid:
            FirewallRuleSourceFactory.build(address=address)
        else:
            with pytest.raises(
                ValidationError,
                match="is not a valid IP address or subnet CIDR",
            ):
                FirewallRuleSourceFactory.build(address=address)

    @pytest.mark.parametrize(
        ("port", "is_valid"),
        ((0, True), (80, True), (65535, True), (-1, False), (65536, False)),
    )
    def test_port_validation(self, port: int, is_valid: bool) -> None:
        if is_valid:
            FirewallRuleSourceFactory.build(port=port)
        else:
            with pytest.raises(
                ValidationError,
                match="is not a valid port number",
            ):
                FirewallRuleSourceFactory.build(port=port)


class TestFirewallPort:
    @pytest.mark.parametrize(
        ("port", "is_valid"),
        ((0, True), (80, True), (65535, True), (-1, False), (65536, False)),
    )
    def test_number_validation(self, port: int, is_valid: bool) -> None:
        if is_valid:
            FirewallRulePortFactory.build(number=port)
        else:
            with pytest.raises(
                ValidationError,
                match="is not a valid port number",
            ):
                FirewallRulePortFactory.build(number=port)
