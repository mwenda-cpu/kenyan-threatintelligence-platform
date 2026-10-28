"""Threat Intelligence REST API blueprint."""

from flask import Blueprint

ti_api = Blueprint("ti_api", __name__, url_prefix="/api/v1")

from . import (  # noqa: E402
    auth,  # noqa: E402,F401
    routes,  # noqa: E402,F401
    schemas,  # noqa: E402,F401
)
