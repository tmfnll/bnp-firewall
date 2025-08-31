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


class TestFilteringPolicies:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/"
            )

            assert response.status_code == 401

        def test_an_authorised_request_is_forbidden(
            self, unauthorised_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthorised_client.get(
                "/firewalls/1/filtering-policies/"
            )

            assert response.status_code == 403

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

            assert data["total"] == 1
            assert data["page"] == 1
            assert data["per_page"] == 10

            items = data["items"]

            assert len(items) == 1
            assert items[0]["id"] == filtering_policy.id
            assert items[0]["name"] == filtering_policy.name

        @pytest.mark.parametrize(
            ("filter", "value"),
            (
                ("name", None),
                ("default_action", "ALLOW"),
            ),
        )
        def test_filter_match(
            self,
            filter: str,
            value: str | None,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:

            value = value or getattr(filtering_policy, filter)

            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/?{filter}={value}"
            )

            assert response.status_code == 200

            assert response.json is not None

            assert response.json["total"] == 1
            assert response.json["items"][0]["id"] == filtering_policy.id

        @pytest.mark.parametrize(
            ("filter", "value"), (("name", "xxx"), ("default_action", "DENY"))
        )
        def test_filter_mismatch(
            self,
            filter: str,
            value: str,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/?{filter}={value}"
            )

            assert response.status_code == 200

            assert response.json is not None

            assert response.json["total"] == 0
            assert response.json["items"] == []

        def test_it_paginates_data(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            another_filtering_policy: FilteringPolicy,
            client: FlaskClient,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/?page_size=1&page=1"
            )

            data = response.json

            assert data is not None

            assert data["total"] == 2
            assert data["page"] == 1
            assert data["per_page"] == 1

            items = data["items"]

            assert len(items) == 1
            assert items[0]["id"] == filtering_policy.id
            assert items[0]["name"] == filtering_policy.name

        @pytest.mark.parametrize(
            ("order_by", "reverse"),
            (
                ("id", False),
                ("-id", True),
                ("name", False),
                ("-name", True),
                ("default_action", False),
                ("-default_action", True),
            ),
        )
        def test_it_sorts_data(
            self,
            firewall: Firewall,
            filtering_policy: FilteringPolicy,
            another_filtering_policy: FilteringPolicy,
            client: FlaskClient,
            order_by: str,
            reverse: bool,
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/?order_by={order_by}"
            )

            assert response.status_code == 200

            if order_by.startswith("-"):
                order_by = order_by[1:]

            data = response.json

            assert data is not None

            assert [item["id"] for item in data["items"]] == [
                filtering_policy_.id
                for filtering_policy_ in sorted(
                    [filtering_policy, another_filtering_policy],
                    key=lambda f: getattr(f, order_by),
                    reverse=reverse,
                )
            ]

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

                assert response.json is not None

                assert response.json["items"] == []

    class TestPost:
        @pytest.fixture
        def payload(self) -> dict[str, Any]:
            return {
                "name": "New FilteringPolicy",
                "default_action": "ALLOW",
            }

        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.post(
                "/firewalls/1/filtering-policies/", json={}
            )

            assert response.status_code == 401

            assert response.json is not None

            assert response.json == {
                "code": 401,
                "status": "Unauthorized",
            }

        def test_an_authorised_request_is_forbidden(
            self, unauthorised_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthorised_client.post(
                "/firewalls/1/filtering-policies/", json={}
            )

            assert response.status_code == 403

            assert response.json is not None

            assert response.json == {
                "code": 403,
                "status": "Forbidden",
            }

        def test_it_creates_a_filtering_policy(
            self,
            firewall: Firewall,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/", json=payload
            )

            assert response.status_code == 201, response.json
            data = response.json

            assert data is not None

            assert "id" in data
            assert data["name"] == "New FilteringPolicy"

        def test_a_422_is_returned_when_an_invalid_name_is_provided(
            self,
            firewall: Firewall,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            payload["name"] = "   "

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/", json=payload
            )

            assert response.status_code == 422, response.json

            assert response.json == {
                "code": 422,
                "status": "Unprocessable Entity",
                "errors": {"json": {"name": ["Cannot be blank"]}},
            }

        def test_two_filtering_policies_with_the_same_name_cannot_be_created(
            self,
            firewall: Firewall,
            client: FlaskClient,
            payload: dict[str, Any],
        ) -> None:
            client.post(
                f"/firewalls/{firewall.id}/filtering-policies/",
                json=payload,
            )

            response = client.post(
                f"/firewalls/{firewall.id}/filtering-policies/",
                json=payload,
            )

            assert response.status_code == 409, response.json

            assert response.json == {
                "code": 409,
                "status": "Conflict",
                "message": "A filtering-policy with the same attributes already exists",
            }

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

            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": "A firewall with id=123 was not found",
            }


class TestFilteringPoliciesById:
    class TestGet:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.get(
                "/firewalls/1/filtering-policies/2/"
            )

            assert response.status_code == 401

        def test_an_authorised_request_is_forbidden(
            self, unauthorised_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthorised_client.get(
                "/firewalls/1/filtering-policies/2/"
            )

            assert response.status_code == 403

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
                assert response.json == {
                    "code": 404,
                    "status": "Not Found",
                    "message": f"A filtering-policy with id={filtering_policy.id} and firewall_id={firewall.id} was not found",
                }

        def test_when_no_filtering_policy_exists_it_returns_404(
            self, firewall: Firewall, client: FlaskClient
        ) -> None:
            response = client.get(
                f"/firewalls/{firewall.id}/filtering-policies/9999/"
            )

            assert response.status_code == 404
            assert response.json == {
                "code": 404,
                "status": "Not Found",
                "message": f"A filtering-policy with id=9999 and firewall_id={firewall.id} was not found",
            }

    class TestDelete:
        def test_an_unauthenticated_request_is_unauthorized(
            self, unauthenticated_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthenticated_client.delete(
                "/firewalls/1/filtering-policies/2/"
            )

            assert response.status_code == 401

        def test_an_authorised_request_is_forbidden(
            self, unauthorised_client: DefaultHeaderFlaskClient
        ) -> None:
            response = unauthorised_client.delete(
                "/firewalls/1/filtering-policies/2/"
            )

            assert response.status_code == 403

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
