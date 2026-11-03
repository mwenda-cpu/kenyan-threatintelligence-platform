"""Minimal hardened HTTP fetch helper.

Provides ``safe_fetch()`` wrapping :mod:`requests` with a timeout and
try/except error handling. Intended as a drop-in for modules that import
``from ..http_client import safe_fetch, SafeFetchError``.

Returns a dict with at least ``status`` (int) and ``body`` (bytes).
"""

from typing import Optional

import requests

__all__ = ["SafeFetchError", "safe_fetch"]


class SafeFetchError(Exception):
    """Raised when a safe_fetch request fails."""


def safe_fetch(
    url: str,
    *,
    method: str = "GET",
    headers: Optional[dict] = None,
    timeout: int = 15,
    allow_redirects: bool = False,
) -> dict:
    """Fetch ``url`` with :mod:`requests`, returning ``{"status", "body"}``.

    Raises :class:`SafeFetchError` on any network/TLS/timeout failure so
    callers can degrade gracefully instead of crashing.
    """
    try:
        resp = requests.request(
            method,
            url,
            headers=headers or {},
            timeout=timeout,
            allow_redirects=allow_redirects,
        )
        return {
            "status": resp.status_code,
            "headers": dict(resp.headers),
            "body": resp.content,
            "url": resp.url,
        }
    except requests.RequestException as exc:
        raise SafeFetchError(str(exc)) from exc
