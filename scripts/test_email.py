"""Diagnostic-only email test script.

Sends real test emails via Resend and Mailgun to confirm which provider
works. Does not touch the database, any user record, or application state.
Safe to run; it only prints outcomes.
"""

import os
import sys
from datetime import datetime, timezone

import requests


def main():
    if len(sys.argv) < 2:
        print("Usage: python scripts/test_email.py <recipient@example.com>")
        sys.exit(2)

    recipient = sys.argv[1]
    resend_api_key = os.getenv("RESEND_API_KEY")
    resend_from = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")
    mailgun_api_key = os.getenv("MAILGUN_API_KEY")
    mailgun_domain = os.getenv("MAILGUN_DOMAIN")

    ts = datetime.now(timezone.utc).isoformat()

    # Section 1 - RESEND TEST
    if not resend_api_key:
        print("RESEND: SKIP (RESEND_API_KEY not set)")
    else:
        try:
            resp = requests.post(
                "https://api.resend.com/emails",
                headers={
                    "Authorization": "Bearer " + resend_api_key,
                    "Content-Type": "application/json",
                },
                json={
                    "from": resend_from,
                    "to": [recipient],
                    "subject": "Kenya TI Platform - Resend test",
                    "html": "<p>Resend test at " + ts + "</p>",
                },
                timeout=10,
            )
            if resp.status_code in (200, 201):
                print(
                    "RESEND: OK status=%s id=%s"
                    % (resp.status_code, resp.json().get("id"))
                )
            else:
                print(
                    "RESEND: FAIL status=%s body=%s"
                    % (resp.status_code, resp.text)
                )
        except Exception as e:
            print("RESEND: EXC %s: %s" % (type(e).__name__, e))

    # Section 2 - MAILGUN TEST
    if not mailgun_api_key or not mailgun_domain:
        print("MAILGUN: SKIP (not configured)")
    else:
        try:
            resp = requests.post(
                "https://api.mailgun.net/v3/" + mailgun_domain + "/messages",
                auth=("api", mailgun_api_key),
                data={
                    "from": "Mailgun Sandbox <postmaster@" + mailgun_domain + ">",
                    "to": [recipient],
                    "subject": "Kenya TI Platform - Mailgun test",
                    "text": "Mailgun test at " + ts,
                },
                timeout=10,
            )
            if resp.status_code == 200:
                print("MAILGUN: OK status=200")
            else:
                print(
                    "MAILGUN: FAIL status=%s body=%s"
                    % (resp.status_code, resp.text)
                )
        except Exception as e:
            print("MAILGUN: EXC %s: %s" % (type(e).__name__, e))

    # Section 3 - SUMMARY
    print("DONE")


if __name__ == "__main__":
    main()
