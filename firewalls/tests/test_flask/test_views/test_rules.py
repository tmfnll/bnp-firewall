from datetime import datetime, timezone
from typing import Any, Callable
from uuid import uuid4

import pytest
from flask.testing import FlaskClient

from conftest import DefaultHeaderFlaskClient
from firewalls.models import (
    FilteringPolicy,
    Firewall,
    FirewallAction,
    FirewallRule,
)


class TestFirewallRules:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/2/rules/"
            )

            assert response.status_code == 401

        def test_it_returns_a_list_of_firewall_rules(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/?source_port={rule.sources[0].port}"
            )

            assert response.status_code == 200

            assert response.json is not None

            (datum,) = response.json["items"]

            assert datum == {
                "id": rule.id,
                "filtering_policy": {
                    "id": filtering_policy.id,
                    "name": filtering_policy.name,
                    "default_action": filtering_policy.default_action.name,
                    "firewall": {
                        "id": firewall.id,
                        "name": firewall.name,
                    },
                },
                "action": rule.action.name,
                "sources": [
                    {
                        "address": source.address,
                        "port": source.port,
                    }
                    for source in rule.sources
                ],
                "destinations": [
                    {
                        "address": destination.address,
                        "port": destination.port,
                    }
                    for destination in rule.destinations
                ],
                "ports": [{"number": port.number} for port in rule.ports],
            }

        @pytest.mark.parametrize(
            ("filter", "value"),
            (
                ("action", lambda r: r.action.name),
                ("source_address", lambda r: r.sources[0].address),
                ("source_port", lambda r: r.sources[0].port),
                ("destination_address", lambda r: r.destinations[0].address),
                ("destination_port", lambda r: r.destinations[0].port),
                ("port", lambda r: r.ports[0].number),
            ),
        )
        def test_filter_match(
            self,
            filter: str,
            value: Callable[[FirewallRule], str],
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            value_str = value(rule)

            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/?{filter}={value_str}"
            )

            assert response.status_code == 200

            assert response.json is not None

            assert response.json["total"] == 1
            assert response.json["items"][0]["id"] == rule.id

        @pytest.mark.parametrize(
            ("filter", "value"),
            (
                (
                    "action",
                    lambda r: (
                        "DENY" if r.action is FirewallAction.ALLOW else "ALLOW"
                    ),
                ),
                ("source_address", lambda r: r.sources[0].address + "/32"),
                ("source_port", lambda r: r.sources[0].port + 1),
                (
                    "destination_address",
                    lambda r: r.destinations[0].address + "/32",
                ),
                ("destination_port", lambda r: r.destinations[0].port + 1),
                ("port", lambda r: r.ports[0].number + 1),
            ),
        )
        def test_filter_mismatch(
            self,
            filter: str,
            value: Callable[[FirewallRule], str],
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            value_str = value(rule)

            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/?{filter}={value_str}"
            )

            assert response.status_code == 200

            assert response.json is not None

            assert response.json["total"] == 0
            assert response.json["items"] == []

        def test_it_paginates_data(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            rule: FirewallRule,
            another_rule: FirewallRule,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/?page_size=1&page=1"
            )

            assert response.json is not None

            data = response.json

            assert data["total"] == 2
            assert data["page"] == 1
            assert data["per_page"] == 1

            (datum,) = data["items"]

            assert datum == {
                "id": rule.id,
                "filtering_policy": {
                    "id": filtering_policy.id,
                    "name": filtering_policy.name,
                    "default_action": filtering_policy.default_action.name,
                    "firewall": {
                        "id": firewall.id,
                        "name": firewall.name,
                    },
                },
                "action": rule.action.name,
                "sources": [
                    {
                        "address": source.address,
                        "port": source.port,
                    }
                    for source in rule.sources
                ],
                "destinations": [
                    {
                        "address": destination.address,
                        "port": destination.port,
                    }
                    for destination in rule.destinations
                ],
                "ports": [{"number": port.number} for port in rule.ports],
            }

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

                assert response.json is not None

                assert response.json["items"] == []

    class TestPost:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.post(
                "/firewalls/1/filtering-policies/2/rules/", json={}
            )

            assert response.status_code == 401

        @pytest.fixture
        def payload(self) -> dict[str, Any]:
            return {
                "sources": [
                    {"address": "100.100.100.0/24", "port": 8080},
                ],
                "destinations": [
                    {"address": "200.200.200.200", "port": 9090},
                ],
                "ports": [{"number": 8080}],
                "action": "ALLOW",
            }

        def test_it_creates_a_rule(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 201, response.json
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["sources"] == [
                {"address": "100.100.100.0/24", "port": 8080}
            ]
            assert data["destinations"] == [
                {"address": "200.200.200.200", "port": 9090}
            ]
            assert data["ports"] == [{"number": 8080}]
            assert data["action"] == "ALLOW"

        def test_it_ignores_unknown_fields(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload[str(uuid4())] = {str(uuid4()): [str(uuid4())]}

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 201, response.json
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["sources"] == [
                {"address": "100.100.100.0/24", "port": 8080}
            ]
            assert data["destinations"] == [
                {"address": "200.200.200.200", "port": 9090}
            ]
            assert data["ports"] == [{"number": 8080}]
            assert data["action"] == "ALLOW"

        def test_the_same_rule_cannot_be_added_twice(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 409, response.json
            assert response.json == {
                "code": 409,
                "status": "Conflict",
                "message": "A rule with the same attributes already exists",
            }

        def test_a_422_is_returned_when_an_invalid_address_is_provided(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload["sources"][0]["address"] = "999.999.999.999"

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 422, response.json
            assert response.json == {
                "code": 422,
                "status": "Unprocessable Entity",
                "errors": {
                    "json": {
                        "sources": {
                            "0": {
                                "address": [
                                    "999.999.999.999 is not a valid IP address or subnet CIDR"
                                ]
                            }
                        }
                    }
                },
            }

        def test_a_422_is_returned_when_an_invalid_source_port_provided(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload["sources"][0]["port"] = -1

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 422, response.json
            assert response.json == {
                "code": 422,
                "status": "Unprocessable Entity",
                "errors": {
                    "json": {
                        "sources": {
                            "0": {"port": ["-1 is not a valid TCP port number"]}
                        }
                    }
                },
            }

        @pytest.mark.parametrize(
            ("relation",),
            (
                ("sources",),
                ("destinations",),
                ("ports",),
            ),
        )
        def test_a_422_is_returned_when_no_related_data_are_provided(
            self,
            relation: str,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload[relation] = []

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 422, response.json
            assert response.json == {
                "code": 422,
                "status": "Unprocessable Entity",
                "errors": {
                    "json": {relation: ["Shorter than minimum length 1."]}
                },
            }

        def test_a_422_is_returned_when_an_invalid_port_provided(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload["ports"][0]["number"] = -1

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id}/rules/",
                json=payload,
            )

            assert response.status_code == 422, response.json
            assert response.json == {
                "code": 422,
                "status": "Unprocessable Entity",
                "errors": {
                    "json": {
                        "ports": {
                            "0": {
                                "number": ["-1 is not a valid TCP port number"]
                            }
                        }
                    }
                },
            }

        def test_the_parent_firewall_does_not_exist_it_returns_404(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id + 1}/filtering-policies/{filtering_policy.id}/rules/",
                json={
                    "sources": [
                        {"address": "100.100.100.0/24", "port": 8080},
                    ],
                    "destinations": [
                        {"address": "200.200.200.200", "port": 9090},
                    ],
                    "ports": [{"number": 8080}],
                    "action": "ALLOW",
                },
            )

            assert response.status_code == 404, response.json
            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": f"A filtering-policy with id={filtering_policy.id} and firewall_id={firewall.id + 1} was not found",
            }

        def test_the_parent_filtering_policy_does_not_exist_it_returns_404(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/{filtering_policy.id + 1}/rules/",
                json={
                    "sources": [
                        {"address": "100.100.100.0/24", "port": 8080},
                    ],
                    "destinations": [
                        {"address": "200.200.200.200", "port": 9090},
                    ],
                    "ports": [{"number": 8080}],
                    "action": "ALLOW",
                },
            )

            assert response.status_code == 404, response.json
            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": f"A filtering-policy with id={filtering_policy.id + 1} and firewall_id={firewall.id} was not found",
            }


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

            assert data == {
                "id": rule.id,
                "filtering_policy": {
                    "id": filtering_policy.id,
                    "name": filtering_policy.name,
                    "default_action": filtering_policy.default_action.name,
                    "firewall": {
                        "id": firewall.id,
                        "name": firewall.name,
                    },
                },
                "action": rule.action.name,
                "sources": [
                    {
                        "address": source.address,
                        "port": source.port,
                    }
                    for source in rule.sources
                ],
                "destinations": [
                    {
                        "address": destination.address,
                        "port": destination.port,
                    }
                    for destination in rule.destinations
                ],
                "ports": [{"number": port.number} for port in rule.ports],
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

            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": f"A rule with id=9999 and filtering_policy_id={filtering_policy.id} and firewall_id={firewall.id} was not found",
            }

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

            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": f"A rule with id=9999 and filtering_policy_id={filtering_policy.id} and firewall_id={firewall.id} was not found",
            }
