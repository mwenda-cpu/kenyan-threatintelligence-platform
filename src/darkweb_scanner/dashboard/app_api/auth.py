"""API key authentication for the read-only Threat Intelligence REST API."""

import hmac
import os
from functools import wraps

from flask import jsonify, request


def require_api_key(func):
    """Require a valid ``X-API-Key`` header matching ``TI_API_KEY``."""

    @wraps(func)
    def wrapper(*args, **kwargs):
        supplied = request.headers.get("X-API-Key", "")
        expected = (os.getenv("TI_API_KEY") or "").strip()
        if not expected or not hmac.compare_digest(supplied, expected):
            return jsonify({"error": "Unauthorized"}), 401
        return func(*args, **kwargs)

    return wrapper
