from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum

from sqlalchemy import ForeignKey
from sqlalchemy.orm import Mapped

from db import BaseModel, db


class Firewall(BaseModel):
    __tablename__ = "firewalls"

    name: Mapped[str] = db.mapped_column(index=True)

    filtering_policies: Mapped[list[FilteringPolicy]] = db.relationship(  # type: ignore[assignment]
        back_populates="firewall",
    )


class FirewallAction(StrEnum):
    ALLOW = "allow"
    DENY = "deny"


class FilteringPolicy(BaseModel):
    __tablename__ = "filtering_policies"

    name: Mapped[str] = db.mapped_column(index=True)

    default_action: Mapped[FirewallAction] = db.mapped_column()

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

    def inspect(self, packet: Packet) -> FirewallAction:
        for rule in self.rules:
            action = rule.inspect(packet)

            if action is not None:
                return action

        return self.default_action


@dataclass(frozen=True)
class Packet:
    source_address: str
    source_port: int
    destination_address: str
    destination_port: int


class FirewallRule(BaseModel):
    __tablename__ = "firewall_rules"

    source_address_pattern: Mapped[str] = db.mapped_column()
    source_port: Mapped[int] = db.mapped_column()

    destination_address_pattern: Mapped[str] = db.mapped_column()
    destination_port: Mapped[int] = db.mapped_column()

    action: Mapped[FirewallAction] = db.mapped_column()

    filtering_policy_id: Mapped[int] = db.mapped_column(
        ForeignKey("filtering_policies.id", ondelete="CASCADE"), index=True
    )
    filtering_policy: Mapped[FilteringPolicy] = db.relationship(  # type: ignore[assignment]
        FilteringPolicy,
        back_populates="rules",
    )

    def matches(self, packet: Packet) -> bool:
        return (
            bool(re.match(self.source_address_pattern, packet.source_address))
            and self.source_port == packet.source_port
            and bool(
                re.match(
                    self.destination_address_pattern, packet.destination_address
                )
            )
            and self.destination_port == packet.destination_port
        )

    def inspect(self, packet: Packet) -> FirewallAction | None:
        if self.matches(packet):
            return self.action

        return None
