from factory import Faker, RelatedFactoryList, SubFactory
from factory.fuzzy import FuzzyChoice

from factories import BaseFactory
from firewalls.models import (
    FilteringPolicy,
    Firewall,
    FirewallAction,
    FirewallRule,
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

    rules = RelatedFactoryList(
        "firewalls.tests.factories.FirewallRuleFactory",
        "filtering_policy",
        size=3,
    )

    class Meta:
        model = FilteringPolicy


class FirewallRuleFactory(BaseFactory):
    source_address_pattern = Faker("ipv4")
    source_port = Faker("pyint", min_value=1000, max_value=20000)

    destination_address_pattern = Faker("ipv4")
    destination_port = Faker("pyint", min_value=1000, max_value=20000)

    action = FuzzyChoice(list(FirewallAction))

    filtering_policy = SubFactory(FilteringPolicyFactory)

    class Meta:
        model = FirewallRule
