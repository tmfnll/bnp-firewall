from typing import Any

from factory import Faker, RelatedFactoryList, SubFactory, post_generation
from factory.base import Factory
from factory.fuzzy import FuzzyChoice

from db import db
from factories import BaseFactory
from firewalls.models import (
    FilteringPolicy,
    Firewall,
    FirewallAction,
    FirewallRule,
    FirewallRuleDestination,
    FirewallRulePort,
    FirewallRuleSource,
)


class FirewallFactory(BaseFactory):
    name = Faker("word")

    filtering_policies = RelatedFactoryList(
        "firewalls.tests.factories.FilteringPolicyFactory", "firewall", size=2
    )

    class Meta:
        model = Firewall


class FilteringPolicyFactory(BaseFactory):
    name = Faker("word")
    default_action = FuzzyChoice(list(FirewallAction))

    firewall = SubFactory(FirewallFactory)

    @post_generation
    @staticmethod
    def rules(
        filtering_policy: FilteringPolicy,
        _create: bool,
        extracted: Any,
        size: int = 2,
        **kwargs: Any
    ) -> None:
        if extracted is None:
            extracted = [
                FirewallRuleFactory.build(
                    **kwargs, filtering_policy=filtering_policy
                )
                for _ in range(size)
            ]

        for rule in extracted:
            with db.session.no_autoflush:
                filtering_policy.rules.append(rule)

    class Meta:
        model = FilteringPolicy


class FirewallRuleFactory(Factory):
    sources = RelatedFactoryList(
        "firewalls.tests.factories.FirewallRuleSourceFactory",
        "firewall_rule",
        size=2,
    )
    destinations = RelatedFactoryList(
        "firewalls.tests.factories.FirewallRuleDestinationFactory",
        "firewall_rule",
        size=2,
    )
    ports = RelatedFactoryList(
        "firewalls.tests.factories.FirewallRulePortFactory",
        "firewall_rule",
        size=2,
    )

    action = FuzzyChoice(list(FirewallAction))

    filtering_policy = SubFactory(FilteringPolicyFactory)

    class Meta:
        model = FirewallRule

    @classmethod
    def build(cls, **kwargs: Any) -> FirewallRule:
        return super().build(**kwargs).set_hashes()

    @classmethod
    def create(cls, **kwargs: Any) -> FirewallRule:
        instance = cls.build(**kwargs)

        db.session.add(instance)
        db.session.commit()

        return instance


class FirewallRuleNetworkAddressFactory(BaseFactory):
    address = Faker("ipv4")
    port = Faker("pyint", min_value=1000, max_value=20000)
    firewall_rule = SubFactory(FirewallRuleFactory)

    class Meta:
        abstract = True


class FirewallRuleSourceFactory(FirewallRuleNetworkAddressFactory):
    class Meta:
        model = FirewallRuleSource


class FirewallRuleDestinationFactory(FirewallRuleNetworkAddressFactory):
    class Meta:
        model = FirewallRuleDestination


class FirewallRulePortFactory(BaseFactory):
    number = Faker("pyint", min_value=1000, max_value=20000)
    firewall_rule = SubFactory(FirewallRuleFactory)

    class Meta:
        model = FirewallRulePort
