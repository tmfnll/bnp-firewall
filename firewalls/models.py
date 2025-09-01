from __future__ import annotations

from abc import abstractmethod
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address, ip_network
from typing import Self

from sqlalchemy import ForeignKey, UniqueConstraint
from sqlalchemy.orm import Mapped, validates

from db import BaseModel, db


class ValidationError(ValueError):
    pass


def validate_name(name: str) -> str:
    name = name.strip()

    if not name:
        raise ValidationError("Name cannot be empty or whitespace")

    return name


class Firewall(BaseModel):
    __tablename__ = "firewalls"

    name: Mapped[str] = db.mapped_column(index=True, unique=True)

    @validates("name")
    def validate_name(self, _key: str, name: str) -> str:
        return validate_name(name)

    filtering_policies: Mapped[list[FilteringPolicy]] = db.relationship(  # type: ignore[assignment]
        back_populates="firewall",
    )


class FirewallAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


@dataclass(frozen=True)
class Inspection:
    action: FirewallAction
    active_rule: FirewallRule | None = None


class FilteringPolicy(BaseModel):
    __tablename__ = "filtering_policies"

    name: Mapped[str] = db.mapped_column(index=True)

    @validates("name")
    def validate_name(self, _key: str, name: str) -> str:
        return validate_name(name)

    default_action: Mapped[FirewallAction] = db.mapped_column(index=True)

    firewall_id: Mapped[int] = db.mapped_column(
        ForeignKey("firewalls.id", ondelete="CASCADE"), index=True
    )
    firewall: Mapped[Firewall] = db.relationship(  # type: ignore[assignment]
        Firewall,
        back_populates="filtering_policies",
    )

    rules: Mapped[list[FirewallRule]] = db.relationship(  # type: ignore[assignment]
        back_populates="filtering_policy",
    )

    @property
    def prioritised_rules(self) -> list[FirewallRule]:
        return sorted(self.rules, key=lambda rule: rule.priority)

    def inspect(self, packet: Packet) -> Inspection:
        for rule in self.prioritised_rules:
            action = rule.inspect(packet)

            if action is not None:
                return Inspection(action, rule)

        return Inspection(self.default_action, None)

    __table_args__ = (
        UniqueConstraint(
            "name", "firewall_id", name="unique_name_and_firewall_id"
        ),
    )


@dataclass(frozen=True)
class Packet:
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int


IP_REGEX = r"((25[0-5]|(2[0-4]|1\d|[1-9]|)\d)\.?\b){4}"


SUBNET_CIDR_REGEX = rf"{IP_REGEX}/([0-9]|[1-2][0-9]|3[0-2])"


ADDRESS_REGEX = rf"({IP_REGEX})|({SUBNET_CIDR_REGEX})"

VALID_TCP_PORT_RANGE = (0, 65535)


def is_valid_port(port: int) -> bool:
    min_, max_ = VALID_TCP_PORT_RANGE

    return min_ <= port <= max_


def validate_port(port: int) -> int:
    if is_valid_port(port):
        return port

    raise ValidationError(f"{port} is not a valid port number")


def validate_ip_address_or_subnet_cidr(address: str) -> str:
    errors: list[str] = []

    try:
        ip_address(address)
    except ValueError as exc:
        errors.append(str(exc))
    else:
        return address

    try:
        ip_network(address)
    except ValueError as exc:
        errors.append(str(exc))
    else:
        return address

    raise ValidationError(f"{address} is not a valid IP address or subnet CIDR")


class FirewallRule(BaseModel):
    __tablename__ = "firewall_rules"

    sources: Mapped[list[FirewallRuleSource]] = db.relationship(  # type: ignore[assignment]
        "FirewallRuleSource", back_populates="firewall_rule"
    )

    source_hash: Mapped[int] = db.mapped_column(index=True)

    destinations: Mapped[list[FirewallRuleDestination]] = db.relationship(  # type: ignore[assignment]
        "FirewallRuleDestination", back_populates="firewall_rule"
    )

    destination_hash: Mapped[int] = db.mapped_column(index=True)

    ports: Mapped[list[FirewallRulePort]] = db.relationship(  # type: ignore[assignment]
        "FirewallRulePort", back_populates="firewall_rule"
    )

    port_hash: Mapped[int] = db.mapped_column(index=True)

    action: Mapped[FirewallAction] = db.mapped_column(index=True)

    priority: Mapped[int] = db.mapped_column(index=True)

    description: Mapped[str] = db.mapped_column(index=False, default="")

    filtering_policy_id: Mapped[int] = db.mapped_column(
        ForeignKey("filtering_policies.id", ondelete="CASCADE"), index=True
    )
    filtering_policy: Mapped[FilteringPolicy] = db.relationship(  # type: ignore[assignment]
        FilteringPolicy,
        back_populates="rules",
    )

    def set_source_hash(self) -> Self:
        self.source_hash = hash(
            frozenset(source.key for source in self.sources)
        )

        return self

    def set_destination_hash(self) -> Self:
        self.destination_hash = hash(
            frozenset(destination.key for destination in self.destinations)
        )

        return self

    def set_port_hash(self) -> Self:
        self.port_hash = hash(frozenset(port.key for port in self.ports))

        return self

    def set_hashes(self) -> Self:
        return self.set_source_hash().set_destination_hash().set_port_hash()

    def matches(self, packet: Packet) -> bool:
        for source in self.sources:
            if not source.matches(packet):
                return False

        for destination in self.destinations:
            if not destination.matches(packet):
                return False

        return True

    def inspect(self, packet: Packet) -> FirewallAction | None:
        if self.matches(packet):
            return self.action

        return None

    __table_args__ = (
        UniqueConstraint(
            "source_hash",
            "destination_hash",
            "port_hash",
            "action",
            "filtering_policy_id",
            name="unique_filtering_policy_action_sources_destinations_ports",
        ),
    )


class FirewallRuleNetworkAddress(BaseModel):
    __abstract__ = True

    address: Mapped[str] = db.mapped_column(index=True)
    port: Mapped[int] = db.mapped_column(index=True)

    @property
    def key(self) -> int:
        return hash((self.address, self.port))

    firewall_rule_id: Mapped[int] = db.mapped_column(
        ForeignKey("firewall_rules.id", ondelete="CASCADE"), index=True
    )

    @validates("address")
    def validate_address(self, _key: str, address: str) -> str:
        return validate_ip_address_or_subnet_cidr(address)

    @validates("port")
    def validate_port(self, _key: str, port: int) -> int:
        return validate_port(port)

    @property
    def is_ip(self) -> bool:
        try:
            ip_address(self.address)
        except ValueError:
            return False

        return True

    def ip_matches(self, ip: str) -> bool:
        if self.is_ip:
            return ip == self.address

        return ip_address(ip) in ip_network(self.address)

    def port_matches(self, port: int) -> bool:
        return port == self.port

    @abstractmethod
    def matches(self, packet: Packet) -> bool:
        raise NotImplementedError()  # pragma: nocover


class FirewallRuleSource(FirewallRuleNetworkAddress):
    __tablename__ = "firewall_rule_sources"

    firewall_rule: Mapped[FirewallRule] = db.relationship(  # type: ignore[assignment]
        FirewallRule,
        back_populates="sources",
    )

    def matches(self, packet: Packet) -> bool:
        return self.ip_matches(packet.source_address) and self.port_matches(
            packet.source_port
        )


class FirewallRuleDestination(FirewallRuleNetworkAddress):
    __tablename__ = "firewall_rule_destinations"

    firewall_rule: Mapped[FirewallRule] = db.relationship(  # type: ignore[assignment]
        FirewallRule,
        back_populates="destinations",
    )

    def matches(self, packet: Packet) -> bool:
        return self.ip_matches(
            packet.destination_address
        ) and self.port_matches(packet.destination_port)


class FirewallRulePort(BaseModel):
    __tablename__ = "firewall_rule_ports"

    number: Mapped[int] = db.mapped_column(index=True)

    firewall_rule_id: Mapped[int] = db.mapped_column(
        ForeignKey("firewall_rules.id", ondelete="CASCADE"), index=True
    )

    firewall_rule: Mapped[FirewallRule] = db.relationship(  # type: ignore[assignment]
        FirewallRule,
        back_populates="ports",
    )

    @validates("number")
    def validate_number(self, _key: str, number: int) -> int:
        return validate_port(number)

    @property
    def key(self) -> int:
        return hash(self.number)
