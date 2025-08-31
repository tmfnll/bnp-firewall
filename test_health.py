from flask.testing import FlaskClient


def test_health(client: FlaskClient) -> None:
    response = client.get("/health/")

    assert response.status_code == 200
    assert response.json == {"status": "OK"}


def test_unauthenticated_calls_to_health(
    unauthenticated_client: FlaskClient,
) -> None:
    response = unauthenticated_client.get("/health/")

    assert response.status_code == 401

    assert response.json is not None

    assert response.json == {
        "code": 401,
        "status": "Unauthorized",
    }


def test_unauthorised_calls_to_health(
    unauthorised_client: FlaskClient,
) -> None:
    response = unauthorised_client.get("/health/")

    assert response.status_code == 403

    assert response.json is not None

    assert response.json == {
        "code": 403,
        "status": "Forbidden",
    }
