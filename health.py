from dataclasses import dataclass
from enum import StrEnum

from flask_smorest import Blueprint
from marshmallow import Schema
from marshmallow.fields import Enum

from auth import require_login

health = Blueprint("health", __name__, url_prefix="/health")

health.before_request(require_login)


class HealthCheckStatus(StrEnum):
    OK = "ok"


@dataclass(frozen=True)
class HealthCheck:
    status: HealthCheckStatus


class HealthCheckSchema(Schema):
    status = Enum(HealthCheckStatus)


@health.route("/", methods=["GET"])
@health.response(200, HealthCheckSchema)
def health_check() -> HealthCheck:
    """
    Health check endpoint to verify the service is running.
    """
    return HealthCheck(HealthCheckStatus.OK)
