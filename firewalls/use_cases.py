from dataclasses import dataclass
from typing import Any

from firewalls.models import (
    FilteringPolicy,
    Firewall,
    FirewallAction,
    FirewallRule,
)
from repository import Repository
from use_case import UseCase


@dataclass(frozen=True)
class CreateFirewallCommand:
    name: str


class CreateFirewall(UseCase[CreateFirewallCommand, Firewall]):
    def _execute(self, command: CreateFirewallCommand) -> Firewall:
        firewall = Firewall(name=command.name)

        self.db.session.add(firewall)

        return firewall


@dataclass(frozen=True)
class CreateFilteringPolicyCommand:
    name: str
    default_action: FirewallAction
    firewall_id: int


class CreateFilteringPolicy(
    UseCase[CreateFilteringPolicyCommand, FilteringPolicy]
):
    def __init__(
        self,
        firewall_repository: Repository[Firewall],
        *args: Any,
        **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.firewall_repository = firewall_repository

    def _execute(
        self, command: CreateFilteringPolicyCommand
    ) -> FilteringPolicy:
        firewall = self.firewall_repository.get(command.firewall_id)

        filtering_policy = FilteringPolicy(
            name=command.name,
            default_action=command.default_action,
            firewall=firewall,
        )

        self.db.session.add(filtering_policy)

        return filtering_policy


@dataclass(frozen=True)
class CreateFirewallRuleCommand:
    source_address_pattern: str
    source_port: int

    destination_address_pattern: str
    destination_port: int

    action: FirewallAction

    filtering_policy_id: int


class CreateFirewallRule(UseCase[CreateFirewallRuleCommand, FirewallRule]):
    def __init__(
        self,
        filtering_policy_repository: Repository[FilteringPolicy],
        *args: Any,
        **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.filtering_policy_repository = filtering_policy_repository

    def _execute(self, command: CreateFirewallRuleCommand) -> FirewallRule:
        filtering_policy = self.filtering_policy_repository.get(
            command.filtering_policy_id
        )

        firewall_rule = FirewallRule(
            source_address_pattern=command.source_address_pattern,
            source_port=command.source_port,
            destination_address_pattern=command.destination_address_pattern,
            destination_port=command.destination_port,
            action=command.action,
            filtering_policy=filtering_policy,
        )

        self.db.session.add(firewall_rule)

        return firewall_rule


@dataclass(frozen=True)
class DeleteFirewallCommand:
    id: int


class DeleteFirewall(UseCase[DeleteFirewallCommand, None]):
    def __init__(
        self,
        firewall_repository: Repository[Firewall],
        *args: Any,
        **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)

        self.firewall_repository = firewall_repository

    def _execute(self, command: DeleteFirewallCommand) -> None:
        firewall = self.firewall_repository.get(command.id)

        firewall.soft_delete()


@dataclass(frozen=True)
class DeleteFilteringPolicyCommand:
    id: int


class DeleteFilteringPolicy(UseCase[DeleteFilteringPolicyCommand, None]):
    def __init__(
        self,
        filtering_policy_repository: Repository[FilteringPolicy],
        *args: Any,
        **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.filtering_policy_repository = filtering_policy_repository

    def _execute(self, command: DeleteFilteringPolicyCommand) -> None:
        filtering_policy = self.filtering_policy_repository.get(command.id)

        filtering_policy.soft_delete()


@dataclass(frozen=True)
class DeleteFirewallRuleCommand:
    id: int


class DeleteFirewallRule(UseCase[DeleteFirewallRuleCommand, None]):
    def __init__(
        self,
        firewall_rule_repository: Repository[FirewallRule],
        *args: Any,
        **kwargs: Any
    ) -> None:
        super().__init__(*args, **kwargs)
        self.firewall_rule_repository = firewall_rule_repository

    def _execute(self, command: DeleteFirewallRuleCommand) -> None:
        firewall_rule = self.firewall_rule_repository.get(command.id)

        firewall_rule.soft_delete()
