from flask.testing import FlaskClient
from werkzeug.test import TestResponse


def _assert_status(response: TestResponse, expected_status: int = 200) -> None:
    assert response.status_code == expected_status, response.json


def _assert_len(response: TestResponse, expected_len: int) -> None:
    _assert_status(response)

    assert response.json is not None

    assert "items" in response.json, response.json

    assert len(response.json["items"]) == expected_len, response.json


def test_firewall_flow(
    client: FlaskClient,
) -> None:
    _assert_len(client.get("/firewalls/"), 0)

    _assert_status(client.post("/firewalls/", json={"name": "one"}), 201)
    _assert_status(client.post("/firewalls/", json={"name": "two"}), 201)
    # Duplicate
    _assert_status(client.post("/firewalls/", json={"name": "two"}), 409)

    _assert_len(client.get("/firewalls/"), 2)

    _assert_status(client.get(f"/firewalls/1/"))
    _assert_status(client.get(f"/firewalls/2/"))

    _assert_status(client.get("/firewalls/1/"))
    _assert_status(client.delete("/firewalls/1/"), 204)
    _assert_status(client.get("/firewalls/1/"), 404)

    _assert_len(client.get("/firewalls/"), 1)

    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/",
            json={"name": "policy_one", "default_action": "ALLOW"},
        ),
        201,
    )

    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/",
            json={"name": "policy_two", "default_action": "DENY"},
        ),
        201,
    )

    # Duplicate
    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/",
            json={"name": "policy_two", "default_action": "DENY"},
        ),
        409,
    )

    _assert_len(client.get("/firewalls/2/filtering-policies/"), 2)

    _assert_status(client.get("/firewalls/2/filtering-policies/1/"))
    _assert_status(client.delete("/firewalls/2/filtering-policies/1/"), 204)
    _assert_status(client.get("/firewalls/2/filtering-policies/1/"), 404)

    _assert_len(client.get("/firewalls/2/filtering-policies/"), 1)

    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/2/rules/",
            json={
                "action": "ALLOW",
                "priority": 100,
                "sources": [{"address": "92.168.1.0/24", "port": 443}],
                "destinations": [{"address": "92.168.1.0/24", "port": 443}],
                "ports": [{"number": 443}],
            },
        ),
        201,
    )

    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/2/rules/",
            json={
                "action": "ALLOW",
                "priority": 100,
                "sources": [{"address": "92.168.2.0/24", "port": 443}],
                "destinations": [{"address": "92.168.2.0/24", "port": 443}],
                "ports": [{"number": 443}],
            },
        ),
        201,
    )

    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/2/rules/",
            json={
                "action": "ALLOW",
                "priority": 100,
                "sources": [{"address": "92.168.3.0/24", "port": 443}],
                "destinations": [{"address": "92.168.3.0/24", "port": 443}],
                "ports": [{"number": 443}],
            },
        ),
        201,
    )

    # Duplicate
    _assert_status(
        client.post(
            "/firewalls/2/filtering-policies/2/rules/",
            json={
                "action": "ALLOW",
                "priority": 100,
                "sources": [{"address": "92.168.3.0/24", "port": 443}],
                "destinations": [{"address": "92.168.3.0/24", "port": 443}],
                "ports": [{"number": 443}],
            },
        ),
        409,
    )

    _assert_len(client.get("/firewalls/2/filtering-policies/2/rules/"), 3)

    _assert_status(client.get(f"/firewalls/2/filtering-policies/2/rules/3/"))
    _assert_status(
        client.delete(f"/firewalls/2/filtering-policies/2/rules/3/"), 204
    )
    _assert_status(
        client.get(f"/firewalls/2/filtering-policies/2/rules/3/"), 404
    )

    _assert_len(client.get("/firewalls/2/filtering-policies/2/rules/"), 2)
