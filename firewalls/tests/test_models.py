from datetime import datetime, timezone

import pytest

from firewalls.models import (
    FilteringPolicy,
    FirewallAction,
    FirewallRule,
    Packet,
)
from firewalls.tests.factories import (
    FilteringPolicyFactory,
    FirewallRuleFactory,
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
        return FirewallRuleFactory.create(
            source_address_pattern=r"\A100\.100\.100\.\d{1,3}\Z",
            source_port=8080,
            destination_address_pattern=r"\A99\.99\.99\.99\Z",
            destination_port=80,
            deleted_at=rule_deleted_at,
        )

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
                source_address_pattern=r"\A100\.100\.100.\d{1,3}\Z",
                source_port=8080,
                destination_address_pattern=r"\A99\.99\.99\.99\Z",
                destination_port=80,
                action=FirewallAction.ALLOW,
            ),
            FirewallRuleFactory.create(
                filtering_policy=filtering_policy,
                source_address_pattern=r"\A200\.200\.200\.\d{1,3}\Z",
                source_port=8080,
                destination_address_pattern=r"\A77\.77\.77\.77\Z",
                destination_port=80,
                action=FirewallAction.DENY,
            ),
        ]

    @pytest.mark.parametrize(
        (
            "source_address",
            "source_port",
            "destination_address",
            "destination_port",
            "expected_action",
        ),
        (
            (
                "100.100.100.1",
                8080,
                "99.99.99.99",
                80,
                FirewallAction.ALLOW,
            ),
            (
                "200.200.200.200",
                8080,
                "77.77.77.77",
                80,
                FirewallAction.DENY,
            ),
            (
                "300.300.300.300",  # Mismatched source address
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
        expected_action: FirewallAction | None,
    ) -> None:
        action = filtering_policy.inspect(packet)

        if expected_action is not None:
            assert action is expected_action
        else:
            assert action is filtering_policy.default_action
