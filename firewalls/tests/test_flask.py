from datetime import datetime, timezone

import pytest
from flask.testing import FlaskClient

from conftest import DefaultHeaderFlaskClient
from firewalls.models import FilteringPolicy, Firewall, FirewallRule
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
        rules=[], firewall=firewall, deleted_at=filtering_policy_deleted_at
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


class TestFirewalls:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get("/firewalls/")

            assert response.status_code == 401

        def test_it_returns_a_list_of_firewalls(
            self, firewall: Firewall, client: FlaskClient
        ) -> None:
            response = client.get(f"/firewalls/?name={firewall.name}")

            assert response.status_code == 200

            data = response.json

            assert data is not None

            assert len(data) == 1
            assert data[0]["id"] == firewall.id
            assert data[0]["name"] == firewall.name

        def test_it_paginates_data(
            self,
            firewall: Firewall,
            another_firewall: Firewall,
            client: FlaskClient,
        ) -> None:
            response = client.get("/firewalls/?per_page=1&page=1")

            data = response.json

            assert data is not None

            assert len(data) == 1
            assert data[0]["id"] == firewall.id
            assert data[0]["name"] == firewall.name

        class TestWhenTheFirewallIsSoftDeleted:
            @pytest.fixture
            def firewall_deleted_at(self) -> datetime:
                return datetime.now(tz=timezone.utc)

            def test_it_returns_an_empty_list(
                self,
                firewall: Firewall,
                client: FlaskClient,
            ) -> None:
                response = client.get(f"/firewalls/")

                assert response.status_code == 200
                assert response.json == []

    class TestPost:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.post("/firewalls/", json={})

            assert response.status_code == 401

        def test_it_creates_a_firewall(self, client: FlaskClient) -> None:
            response = client.post(
                "/firewalls/",
                json={
                    "name": "New Firewall",
                },
            )

            assert response.status_code == 201
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["name"] == "New Firewall"


class TestFirewallsById:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get("/firewalls/1/")

            assert response.status_code == 401

        def test_it_returns_the_firewall(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(f"/firewalls/{firewall.id}/")

            assert response.status_code == 200
            data = response.json

            assert data is not None

            assert data["id"] == firewall.id
            assert data["name"] == firewall.name
            assert data["filtering_policies"] == [
                {
                    "id": filtering_policy.id,
                    "name": filtering_policy.name,
                    "default_action": filtering_policy.default_action.name,
                    "rules": [
                        {
                            "id": rule.id,
                            "action": rule.action.name,
                            "source_address_pattern": rule.source_address_pattern,
                            "source_port": rule.source_port,
                            "destination_address_pattern": rule.destination_address_pattern,
                            "destination_port": rule.destination_port,
                        }
                    ],
                }
            ]

        class TestWhenTheFirewallIsSoftDeleted:
            @pytest.fixture
            def firewall_deleted_at(self) -> datetime:
                return datetime.now(tz=timezone.utc)

            def test_it_returns_404(
                self,
                firewall: Firewall,
                client: FlaskClient,
            ) -> None:
                response = client.get(f"/firewalls/{firewall.id}/")

                assert response.status_code == 404

        def test_when_no_firewall_exists_it_returns_404(
            self, client: FlaskClient
        ) -> None:
            response = client.get("/firewalls/9999/")

            assert response.status_code == 404

    class TestDelete:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.delete("/firewalls/1/")

            assert response.status_code == 401

        def test_it_soft_deletes_the_firewall(
            self,
            firewall: Firewall,
            client: FlaskClient,
        ) -> None:
            response = client.delete(f"/firewalls/{firewall.id}/")

            assert response.status_code == 204

            response = client.get(f"/firewalls/{firewall.id}/")
            assert response.status_code == 404

        def test_when_no_firewall_exists_it_returns_404(
            self, client: FlaskClient
        ) -> None:
            response = client.delete("/firewalls/9999/")

            assert response.status_code == 404, response.json


class TestFilteringPolicies:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/"
            )

            assert response.status_code == 401

        def test_it_returns_a_list_of_filtering_policies(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/?name={filtering_policy.name}"
            )

            assert response.status_code == 200

            data = response.json

            assert data is not None

            assert len(data) == 1
            assert data[0]["id"] == filtering_policy.id
            assert data[0]["name"] == filtering_policy.name

        def test_it_paginates_data(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            another_filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/?per_page=1&page=1"
            )

            data = response.json

            assert data is not None

            assert len(data) == 1
            assert data[0]["id"] == filtering_policy.id
            assert data[0]["name"] == filtering_policy.name

        class TestWhenTheFilteringPolicyIsSoftDeleted:
            @pytest.fixture
            def filtering_policy_deleted_at(self) -> datetime:
                return datetime.now(tz=timezone.utc)

            def test_it_returns_an_empty_list(
                self,
                firewall: Firewall,
                filtering_policy: FilteringPolicy,
                client: FlaskClient,
            ) -> None:
                response = client.get(
                    f"/firewalls/{firewall.id}/filtering-policies/"
                )

                assert response.status_code == 200
                assert response.json == []

    class TestPost:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.post(
                "/firewalls/1/filtering-policies/", json={}
            )

            assert response.status_code == 401

        def test_it_creates_a_filtering_policy(
            self, firewall: Firewall, client: FlaskClient
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/",
                json={
                    "name": "New FilteringPolicy",
                    "default_action": "ALLOW",
                },
            )

            assert response.status_code == 201, response.json
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["name"] == "New FilteringPolicy"

        def test_the_parent_firewall_does_not_exist_it_returns_404(
            self, firewall: Firewall, client: FlaskClient
        ) -> None:
            response = client.post(
                "/firewalls/123/filtering-policies/",
                json={
                    "name": "New FilteringPolicy",
                    "default_action": "ALLOW",
                },
            )

            assert response.status_code == 404, response.json


class TestFilteringPoliciesById:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/2/"
            )

            assert response.status_code == 401

        def test_it_returns_the_filtering_policy(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/"
            )

            assert response.status_code == 200
            data = response.json

            assert data is not None
            assert data["id"] == filtering_policy.id
            assert data["name"] == filtering_policy.name
            assert data["firewall"] == {
                "id": firewall.id,
                "name": firewall.name,
            }
            assert data["rules"] == [
                {
                    "id": rule.id,
                    "action": rule.action.name,
                    "source_address_pattern": rule.source_address_pattern,
                    "source_port": rule.source_port,
                    "destination_address_pattern": rule.destination_address_pattern,
                    "destination_port": rule.destination_port,
                }
            ]

        class TestWhenTheFilteringPolicyIsSoftDeleted:
            @pytest.fixture
            def filtering_policy_deleted_at(self) -> datetime:
                return datetime.now(tz=timezone.utc)

            def test_it_returns_404(
                self,
                firewall: Firewall,
                filtering_policy: FilteringPolicy,
                client: FlaskClient,
            ) -> None:
                response = client.get(
                    f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/"
                )

                assert response.status_code == 404

        def test_when_no_filtering_policy_exists_it_returns_404(
            self, firewall: Firewall, client: FlaskClient
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/9999/"
            )

            assert response.status_code == 404

    class TestDelete:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.delete(
                "/firewalls/1/filtering-policies/2/"
            )

            assert response.status_code == 401

        def test_it_soft_deletes_the_filtering_policy(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.delete(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/"
            )

            assert response.status_code == 204

            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/"
            )
            assert response.status_code == 404

        def test_when_no_filtering_policy_exists_it_returns_404(
            self,
            client: FlaskClient,
            firewall: Firewall,
        ) -> None:

            response = client.delete(
                f"/firewalls/{firewall.id}/filtering-policies/9999/"
            )

            assert response.status_code == 404


class TestFirewallRules:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/2/rules/"
            )

            assert response.status_code == 401

        def test_it_returns_a_list_of_filtering_policies(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/?source_port={rule.source_port}"
            )

            assert response.status_code == 200

            assert response.json is not None

            (datum,) = response.json

            assert datum["id"] == rule.id
            assert datum["action"] == rule.action.name
            assert (
                datum["source_address_pattern"] == rule.source_address_pattern
            )
            assert datum["source_port"] == rule.source_port
            assert (
                datum["destination_address_pattern"]
                == rule.destination_address_pattern
            )
            assert datum["destination_port"] == rule.destination_port

        def test_it_paginates_data(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            another_rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/?per_page=1&page=1"
            )

            assert response.json is not None

            (datum,) = response.json

            assert datum["id"] == rule.id
            assert datum["action"] == rule.action.name
            assert (
                datum["source_address_pattern"] == rule.source_address_pattern
            )
            assert datum["source_port"] == rule.source_port
            assert (
                datum["destination_address_pattern"]
                == rule.destination_address_pattern
            )
            assert datum["destination_port"] == rule.destination_port

        class TestWhenTheFirewallRuleIsSoftDeleted:
            @pytest.fixture
            def rule_deleted_at(self) -> datetime:
                return datetime.now(tz=timezone.utc)

            def test_it_returns_an_empty_list(
                self,
                firewall: Firewall,
                filtering_policy: FilteringPolicy,
                rule: FirewallRule,
                client: FlaskClient,
            ) -> None:
                response = client.get(
                    f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/"
                )

                assert response.status_code == 200
                assert response.json == []

    class TestPost:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.post(
                "/firewalls/1/filtering-policies/2/rules/", json={}
            )

            assert response.status_code == 401

        def test_it_creates_a_rule(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json={
                    "source_address_pattern": "100.100.100.100",
                    "destination_address_pattern": "200.200.200.200",
                    "source_port": "8080",
                    "destination_port": "9090",
                    "action": "ALLOW",
                },
            )

            assert response.status_code == 201, response.json
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["source_address_pattern"] == "100.100.100.100"
            assert data["destination_address_pattern"] == "200.200.200.200"
            assert data["source_port"] == 8080
            assert data["destination_port"] == 9090
            assert data["action"] == "ALLOW"

        def test_the_parent_firewall_does_not_exist_it_returns_404(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id + 1}/filtering-policies/{filtering_policy.id}/rules/",
                json={
                    "source_address_pattern": "100.100.100.100",
                    "destination_address_pattern": "200.200.200.200",
                    "source_port": "8080",
                    "destination_port": "9090",
                    "action": "ALLOW",
                },
            )

            assert response.status_code == 404, response.json

        def test_the_parent_filtering_policy_does_not_exist_it_returns_404(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id + 1}/rules/",
                json={
                    "source_address_pattern": "100.100.100.100",
                    "destination_address_pattern": "200.200.200.200",
                    "source_port": "8080",
                    "destination_port": "9090",
                    "action": "ALLOW",
                },
            )

            assert response.status_code == 404, response.json


class TestFirewallRulesById:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/2/rules/3/"
            )

            assert response.status_code == 401

        def test_it_returns_the_rule(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/{rule.id}/"
            )

            assert response.status_code == 200
            data = response.json

            assert data is not None

            assert data["id"] == rule.id
            assert data["action"] == rule.action.name
            assert data["source_address_pattern"] == rule.source_address_pattern
            assert data["source_port"] == rule.source_port
            assert (
                data["destination_address_pattern"]
                == rule.destination_address_pattern
            )
            assert data["destination_port"] == rule.destination_port
            assert data["filtering_policy"] == {
                "id": filtering_policy.id,
                "name": filtering_policy.name,
                "default_action": filtering_policy.default_action.name,
                "firewall": {
                    "id": firewall.id,
                    "name": firewall.name,
                },
            }

        class TestWhenTheFirewallRuleIsSoftDeleted:
            @pytest.fixture
            def rule_deleted_at(self) -> datetime:
                return datetime.now(tz=timezone.utc)

            def test_it_returns_404(
                self,
                firewall: Firewall,
                filtering_policy: FilteringPolicy,
                rule: FirewallRule,
                client: FlaskClient,
            ) -> None:
                response = client.get(
                    f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/{rule.id}/"
                )

                assert response.status_code == 404

        def test_when_no_rule_exists_it_returns_404(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/9999/"
            )

            assert response.status_code == 404

    class TestDelete:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.delete(
                "/firewalls/1/filtering-policies/2/rules/3/"
            )

            assert response.status_code == 401

        def test_it_soft_deletes_the_rule(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.delete(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/{rule.id}/"
            )

            assert response.status_code == 204

            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/{rule.id}/"
            )
            assert response.status_code == 404

        def test_when_no_rule_exists_it_returns_404(
            self,
            client: FlaskClient,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
        ) -> None:

            response = client.delete(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/9999/"
            )

            assert response.status_code == 404
