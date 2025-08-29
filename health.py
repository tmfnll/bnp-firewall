from dataclasses import dataclass
from enum import StrEnum

from flask_smorest import Blueprint
from marshmallow import Schema
from marshmallow.fields import Enum

from auth import auth

health = Blueprint("health", __name__, url_prefix="/health")


class HealthCheckStatus(StrEnum):
    OK = "ok"


@dataclass(frozen=True)
class HealthCheck:
    status: HealthCheckStatus


class HealthCheckSchema(Schema):
    status = Enum(HealthCheckStatus)


@health.route("/", methods=["GET"])
@health.response(200, HealthCheckSchema)
@auth.login_required
def health_check() -> HealthCheck:
    """
    Health check endpoint to verify the service is running.
    """
    return HealthCheck(HealthCheckStatus.OK)
