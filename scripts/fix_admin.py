"""One-shot, idempotent repair script for the admin user row.

Fixes the admin row confirmed via psql:
    id=1  username=admin  email=NULL  is_admin=t  is_verified=f  is_approved=f
and demotes any stray admin rows (e.g. id=2 with is_admin=True left over from
the old hardcoded-admin registration bug).

Safe to re-run: it only updates the target admin row and demotes stray admins,
never drops or alters schema, and never creates duplicate users.
"""

import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from darkweb_scanner.auth import hash_password  # noqa: E402
from darkweb_scanner.storage import User, get_storage  # noqa: E402


def main():
    admin_username = os.getenv("ADMIN_USERNAME", "admin")
    admin_email = os.getenv("ADMIN_EMAIL")
    admin_password = os.getenv("ADMIN_PASSWORD")

    if not admin_password:
        print("ERROR: ADMIN_PASSWORD not set in container env")
        sys.exit(1)

    if not admin_email:
        print("WARN: ADMIN_EMAIL not set; admin email will remain as-is.")

    storage = get_storage()
    with storage.get_session() as db:
        u = db.query(User).filter(User.username == admin_username).first()

        if u is not None:
            print("Fixing existing user '%s' (id=%s)" % (admin_username, u.id))
            u.password_hash = hash_password(admin_password)
            u.is_admin = True
            u.is_verified = True
            u.is_approved = True
            u.must_change_password = False
            u.totp_enabled = False
            u.totp_secret = None
            if admin_email:
                u.email = admin_email
        else:
            print("No user '%s' - creating it" % admin_username)
            u = User(
                username=admin_username,
                email=admin_email,
                password_hash=hash_password(admin_password),
                is_admin=True,
                is_verified=True,
                is_approved=True,
                must_change_password=False,
            )
            db.add(u)

        stray = (
            db.query(User)
            .filter(User.is_admin.is_(True), User.username != admin_username)
            .all()
        )
        demoted = 0
        for s in stray:
            s.is_admin = False
            demoted += 1
            print("Demoting stray admin: id=%s user=%s -> is_admin=False" % (s.id, s.username))

        db.commit()

    print("DONE: '%s' verified+approved+password reset" % admin_username)
    print("      stray admins demoted: %s" % demoted)


if __name__ == "__main__":
    main()
