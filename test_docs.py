import pytest
from flask.testing import FlaskClient


@pytest.mark.parametrize(
    ("path",),
    (
        ("/docs/swagger-ui",),
        ("/docs/openapi.json",),
    ),
)
def test_we_can_access_the_docs_without_authentication(
    unauthenticated_client: FlaskClient,
    path: str,
) -> None:
    response = unauthenticated_client.get(path)
    assert response.status_code == 200
