"""Create the initial admin user.

Reads ADMIN_USERNAME, ADMIN_EMAIL, ADMIN_PASSWORD from the environment
(.env is loaded automatically) and creates a user that bypasses email
verification and admin approval (is_admin=True, is_verified=True,
is_approved=True).
"""

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

try:
    from dotenv import load_dotenv

    load_dotenv(_REPO_ROOT / ".env")
except Exception:
    # dotenv not installed; rely on environment variables already set.
    pass

from darkweb_scanner.auth import hash_password  # noqa: E402
from darkweb_scanner.storage import get_storage  # noqa: E402


def main() -> int:
    username = (os.getenv("ADMIN_USERNAME") or "").strip()
    email = (os.getenv("ADMIN_EMAIL") or "").strip()
    password = os.getenv("ADMIN_PASSWORD") or ""

    missing = [
        name
        for name, value in (
            ("ADMIN_USERNAME", username),
            ("ADMIN_EMAIL", email),
            ("ADMIN_PASSWORD", password),
        )
        if not value
    ]
    if missing:
        print(
            "Missing required env vars: "
            + ", ".join(missing)
            + "\nSet them in .env or export before running, e.g.\n"
            "  ADMIN_USERNAME=admin ADMIN_EMAIL=admin@example.com "
            "ADMIN_PASSWORD=changeme python scripts/create_admin.py",
            file=sys.stderr,
        )
        return 1

    storage = get_storage()
    if storage.get_user_by_username(username):
        print("Admin already exists, skipping.")
        return 0

    storage.create_user(
        username=username,
        email=email,
        password_hash=hash_password(password),
        is_admin=True,
        is_verified=True,
        is_approved=True,
    )
    print(f"Admin created: {username} ({email})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
