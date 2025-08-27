from flask.testing import FlaskClient


def test_health(client: FlaskClient) -> None:
    response = client.get("/health/")

    assert response.status_code == 200
    assert response.json == {"status": "OK"}


def test_unauthorized_calls_to_health(
    unauthenticated_client: FlaskClient,
) -> None:
    response = unauthenticated_client.get("/health/")

    assert response.status_code == 401
