"""
Push STIX threat intel to the KE-CIRT webhook.

Reads ``KE_CIRT_WEBHOOK_URL`` from the environment. If it is unset, prints
setup instructions and exits 0.

CLI: python scripts/push_to_ke_cirt.py
"""

from __future__ import annotations

import logging
import os

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger(__name__)

STIX_URL = "http://localhost/api/v1/export/stix"


def push_to_ke_cirt() -> int:
    webhook_url = (os.getenv("KE_CIRT_WEBHOOK_URL") or "").strip()
    if not webhook_url:
        print("KE_CIRT_WEBHOOK_URL is not set.")
        print("Add it to .env, for example:")
        print('  KE_CIRT_WEBHOOK_URL=https://ke-cirt.go.ke/webhooks/stix')
        print("Then re-run: python scripts/push_to_ke_cirt.py")
        return 0

    ti_api_key = (os.getenv("TI_API_KEY") or "").strip()
    headers = {"X-API-Key": ti_api_key} if ti_api_key else {}

    try:
        resp = requests.get(STIX_URL, headers=headers, timeout=30)
        resp.raise_for_status()
        stix_bundle = resp.text

        webhook_headers = {"Content-Type": "application/stix+json;version=2.1"}
        push = requests.post(
            webhook_url, data=stix_bundle, headers=webhook_headers, timeout=30
        )
        if push.status_code < 400:
            logger.info("STIX bundle pushed to KE-CIRT webhook (status %s)", push.status_code)
        else:
            logger.error(
                "KE-CIRT webhook returned status %s: %s", push.status_code, push.text[:500]
            )
    except Exception:  # noqa: BLE001 - log and continue, never crash the caller
        logger.exception("Failed to push STIX bundle to KE-CIRT")
    return 0


if __name__ == "__main__":
    raise SystemExit(push_to_ke_cirt())
