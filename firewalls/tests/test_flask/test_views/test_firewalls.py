from datetime import datetime, timezone
from typing import Any

import pytest
from flask.testing import FlaskClient

from conftest import DefaultHeaderFlaskClient
from firewalls.models import (
    FilteringPolicy,
    Firewall,
    FirewallRule,
)


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
            response = client.get("/firewalls/")

            assert response.status_code == 200

            data = response.json

            assert data is not None

            assert data["total"] == 1
            assert data["page"] == 1
            assert data["per_page"] == 10

            items = data["items"]

            assert len(items) == 1
            assert items[0]["id"] == firewall.id
            assert items[0]["name"] == firewall.name

        @pytest.mark.parametrize(("filter",), (("name",),))
        def test_filter_match(
            self, filter: str, firewall: Firewall, client: FlaskClient
        ) -> None:
            response = client.get(
                f"/firewalls/?{filter}={getattr(firewall, filter)}"
            )

            assert response.status_code == 200

            assert response.json is not None

            assert response.json["total"] == 1
            assert response.json["items"][0]["id"] == firewall.id

        @pytest.mark.parametrize(("filter", "value"), (("name", "xxx"),))
        def test_filter_mismatch(
            self,
            filter: str,
            value: str,
            firewall: Firewall,
            client: FlaskClient,
        ) -> None:
            response = client.get(f"/firewalls/?{filter}={value}")

            assert response.status_code == 200

            assert response.json is not None

            assert response.json["total"] == 0
            assert response.json["items"] == []

        def test_it_paginates_data(
            self,
            firewall: Firewall,
            another_firewall: Firewall,
            client: FlaskClient,
        ) -> None:
            response = client.get("/firewalls/?page_size=1&page=1")

            data = response.json

            assert data is not None

            assert data["total"] == 2
            assert data["page"] == 1
            assert data["per_page"] == 1

            (item,) = data["items"]

            assert item["id"] == firewall.id
            assert item["name"] == firewall.name

        @pytest.mark.parametrize(
            ("order_by", "reverse"),
            (("id", False), ("-id", True), ("name", False), ("-name", True)),
        )
        def test_it_sorts_data(
            self,
            firewall: Firewall,
            another_firewall: Firewall,
            client: FlaskClient,
            order_by: str,
            reverse: bool,
        ) -> None:
            response = client.get(f"/firewalls/?order_by={order_by}")

            assert response.status_code == 200

            if order_by.startswith("-"):
                order_by = order_by[1:]

            data = response.json

            assert data is not None

            assert [item["id"] for item in data["items"]] == [
                firewall_.id
                for firewall_ in sorted(
                    [firewall, another_firewall],
                    key=lambda f: getattr(f, order_by),
                    reverse=reverse,
                )
            ]

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
                assert response.json == {
                    "items": [],
                    "total": 0,
                    "page": 1,
                    "per_page": 10,
                }

    class TestPost:
        @pytest.fixture
        def payload(self) -> dict[str, Any]:
            return {
                "name": "New Firewall",
            }

        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.post("/firewalls/", json={})

            assert response.status_code == 401

        def test_it_creates_a_firewall(
            self, client: FlaskClient, payload: dict[str, Any]
        ) -> None:
            response = client.post(
                "/firewalls/",
                json=payload,
            )

            assert response.status_code == 201
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["name"] == "New Firewall"

        def test_a_422_is_returned_when_an_invalid_name_is_provided(
            self,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload["name"] = "   "

            response = client.post(f"/firewalls/", json=payload)

            assert response.status_code == 422, response.json

            assert response.json == {
                "code": 422,
                "status": "Unprocessable Entity",
                "errors": {"json": {"name": ["Cannot be blank"]}},
            }

        def test_the_same_firewall_cannot_be_created_twice(
            self, client: FlaskClient, payload: dict[str, Any]
        ) -> None:
            client.post(
                "/firewalls/",
                json=payload,
            )

            response = client.post(
                "/firewalls/",
                json=payload,
            )

            assert response.status_code == 409
            data = response.json

            assert data == {
                "code": 409,
                "status": "Conflict",
                "message": "A firewall with the same attributes already exists",
            }


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
                            "ports": [
                                {"number": port.number} for port in rule.ports
                            ],
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
                assert response.json == {
                    "code": 404,
                    "status": "Not Found",
                    "message": f"A firewall with id={firewall.id} was not found",
                }

        def test_when_no_firewall_exists_it_returns_404(
            self, client: FlaskClient
        ) -> None:
            response = client.get("/firewalls/9999/")

            assert response.status_code == 404
            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": "A firewall with id=9999 was not found",
            }

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
