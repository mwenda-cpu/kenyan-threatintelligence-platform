"""
Auth blueprint — login, register, TOTP setup/verify, OAuth, logout.
"""

import logging
import os
import secrets
import threading
from datetime import datetime, timedelta
from urllib.parse import urlencode

import requests as http_requests
from flask import Blueprint, flash, redirect, render_template, request, session, url_for

from ..auth import (
    check_password,
    generate_totp_qr_base64,
    generate_totp_secret,
    get_oauth_providers,
    hash_password,
    login_user,
    logout_user,
    validate_password_strength,
    verify_totp,
)
from ..storage import User
from .storage_helper import get_storage

logger = logging.getLogger(__name__)
auth_bp = Blueprint("auth", __name__)


def _safe_next(next_url: str, default: str) -> str:
    """Return next_url only when it is a safe same-site path."""
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return default


def send_reset_email(to_email: str, reset_url: str) -> bool:
    """Send a password reset email via Resend.

    Returns True on success, False on failure (error is logged).
    """
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")

    if not api_key:
        logger.error("RESEND_API_KEY not set; cannot send email to %s", to_email)
        return False

    try:
        resp = http_requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_email,
                "to": [to_email],
                "subject": "Reset your Kenya TI Platform password",
                "html": (
                    f"<p>Click to reset your password:</p>"
                    f"<p><a href='{reset_url}'>{reset_url}</a></p>"
                    f"<p>If you did not request this, ignore this email.</p>"
                ),
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            logger.info("Password reset email sent to %s", to_email)
            return True
        logger.error("Resend API Error: %s", resp.text)
        return False
    except Exception as e:  # noqa: BLE001 - never crash the auth flow on email failure
        logger.error(
            "Failed to send password reset email to %s: %s", to_email, e
        )
        return False


def send_verification_email(to_email: str, username: str, token: str) -> bool:
    """Send an email verification link via Resend.

    Returns True on success, False on failure (error is logged).
    """
    api_key = os.getenv("RESEND_API_KEY")
    from_email = os.getenv("RESEND_FROM_EMAIL", "onboarding@resend.dev")
    base_url = os.getenv("BASE_URL", "http://localhost:8080").rstrip("/")
    verify_url = f"{base_url}/verify/{token}"

    if not api_key:
        logger.error("RESEND_API_KEY not set; cannot send email to %s", to_email)
        return False

    try:
        resp = http_requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": from_email,
                "to": [to_email],
                "subject": "Verify your Kenya TI Platform account",
                "html": (
                    f"<p>Hello {username},</p>"
                    f"<p>Click to verify your account:</p>"
                    f"<p><a href='{verify_url}'>{verify_url}</a></p>"
                    f"<p>This link expires in 24 hours.</p>"
                ),
            },
            timeout=10,
        )
        if resp.status_code in (200, 201):
            logger.info("Verification email sent to %s", to_email)
            return True
        logger.error("Resend API Error: %s", resp.text)
        return False
    except http_requests.exceptions.RequestException as e:
        body = e.response.text if getattr(e, "response", None) is not None else str(e)
        logger.error("Resend API Error: %s", body)
        return False
    except Exception as e:  # noqa: BLE001 - never crash the auth flow on email failure
        logger.error("Failed to send verification email to %s: %s", to_email, e)
        return False


# ── Registration ───────────────────────────────────────────────────────────────


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    storage = get_storage()

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm_password", "")

        if not username or not email or not password:
            flash("Username, email, and password are required.", "error")
            return render_template("register.html")

        if username.startswith("admin_"):
            flash("Usernames starting with 'admin_' are reserved.", "error")
            return render_template("register.html")

        if storage.get_user_by_username(username):
            flash("Username already taken.", "error")
            return render_template("register.html")

        if storage.get_user_by_email(email):
            flash("An account with that email already exists.", "error")
            return render_template("register.html")

        if password != confirm:
            flash("Passwords do not match.", "error")
            return render_template("register.html")

        err = validate_password_strength(password)
        if err:
            flash(err, "error")
            return render_template("register.html")

        token = secrets.token_urlsafe(32)
        try:
            storage.create_user(
                username=username,
                email=email,
                password_hash=hash_password(password),
                is_admin=False,
                is_verified=False,
                is_approved=False,
                verification_token=token,
                verification_sent_at=datetime.utcnow(),
            )
        except Exception as e:  # noqa: BLE001 - never expose raw errors to the client
            logger.error("Failed to create account for %s: %s", username, e)
            flash("Could not create account. Please try again.", "error")
            return render_template("register.html")

        try:
            if not send_verification_email(email, username, token):
                logger.error(
                    "Verification email send returned False for %s (%s)", username, email
                )
                # Account still created so the user can request a re-send later.
        except Exception as e:  # noqa: BLE001 - email failure must not block registration
            logger.error("Verification email failed for %s: %s", username, e)

        flash("Check your email to verify your account.", "info")
        return redirect(url_for("auth.verify_notice"))

    return render_template("register.html")


@auth_bp.route("/verify/<token>")
def verify_token(token):
    """Verify a user's email using a time-limited verification token."""
    storage = get_storage()
    with storage.get_session() as db:
        user = db.query(User).filter(User.verification_token == token).first()

    if not user:
        flash("Invalid verification link.", "error")
        return redirect(url_for("auth.register"))

    if (
        not user.verification_sent_at
        or user.verification_sent_at < datetime.utcnow() - timedelta(hours=24)
    ):
        flash("Verification link has expired. Register again to request a new link.", "error")
        return redirect(url_for("auth.register"))

    user.is_verified = True
    user.verification_token = None
    db.commit()
    flash("Email verified! An admin must approve your account before you can log in.", "success")
    return redirect(url_for("auth.login"))


@auth_bp.route("/verify_notice")
def verify_notice():
    """Shown after registration while the user awaits email verification + approval."""
    return render_template("verify_notice.html")


# ── Password Reset ─────────────────────────────────────────────────────────────


@auth_bp.route("/reset_password", methods=["GET", "POST"])
def reset_password():
    """Request a password reset link (sent via Mailgun when configured)."""
    if session.get("logged_in"):
        return redirect(url_for("dashboard.index"))

    storage = get_storage()

    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        if not email:
            flash("Email is required.", "error")
            return render_template("reset_password.html")

        user = storage.get_user_by_email(email)
        if not user:
            # Don't reveal whether the email exists.
            flash(
                "If an account with that email exists, a reset link has been "
                "sent to that address.",
                "info",
            )
            return render_template("reset_password.html")

        token = storage.create_password_reset_token(email)
        base_url = os.getenv("BASE_URL", "").rstrip("/")
        reset_url = f"{base_url}/reset_password/{token}" if base_url else url_for(
            "auth.reset_password_confirm", token=token, _external=True
        )

        def _bg_send():
            try:
                if not send_reset_email(email, reset_url):
                    logger.error(
                        "Background email failed for %s: Mailgun send returned False",
                        email,
                    )
            except Exception as e:  # noqa: BLE001 - log and continue
                logger.error("Background email failed: %s", e)

        threading.Thread(target=_bg_send, daemon=True).start()
        flash(
            "If an account exists, a reset link has been sent to that address.",
            "info",
        )
        return redirect("/login")

    return render_template("reset_password.html")


@auth_bp.route("/reset_password/<token>", methods=["GET", "POST"])
def reset_password_confirm(token):
    """Set a new password using a reset token."""
    if session.get("logged_in"):
        return redirect(url_for("dashboard.index"))

    storage = get_storage()

    # Find the email associated with this token by scanning in-memory store.
    email = None
    for cand_email, entry in storage._RESET_TOKENS.items():
        if entry["token"] == token:
            email = cand_email
            break

    if email is None:
        flash("Invalid or expired reset token.", "error")
        return redirect(url_for("auth.reset_password"))

    user = storage.get_user_by_email(email)
    if not user:
        flash("Account not found.", "error")
        return redirect(url_for("auth.reset_password"))

    if request.method == "POST":
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if not new_pw or new_pw != confirm:
            flash("Passwords must match and not be empty.", "error")
            return render_template("reset_confirm.html", token=token)

        err = validate_password_strength(new_pw)
        if err:
            flash(err, "error")
            return render_template("reset_confirm.html", token=token)

        if not storage.consume_password_reset_token(email, token):
            flash("Invalid or expired reset token.", "error")
            return redirect(url_for("auth.reset_password"))

        storage.update_user_password(user.id, hash_password(new_pw))
        flash("Password reset successful. You can now sign in.", "success")
        return redirect("/login")

    return render_template("reset_confirm.html", token=token)


# ── Login ──────────────────────────────────────────────────────────────────────


@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if session.get("logged_in"):
        return redirect(url_for("dashboard.index"))

    storage = get_storage()

    if storage.count_users() == 0:
        return redirect(url_for("auth.register"))

    oauth_providers = get_oauth_providers()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = storage.get_user_by_username(username)
        if not user or not user.password_hash:
            flash("Invalid username or password.", "error")
            return render_template("login.html", oauth_providers=oauth_providers)

        if not check_password(password, user.password_hash):
            flash("Invalid username or password.", "error")
            return render_template("login.html", oauth_providers=oauth_providers)

        if user.totp_enabled and user.totp_secret:
            session["totp_pending_user_id"] = user.id
            session["totp_pending_username"] = user.username
            return redirect(url_for("auth.totp_verify"))

        # Email verification + admin approval gates (admins skip approval only).
        if not user.is_verified:
            flash("Please verify your email first. Check your inbox.", "error")
            return render_template("login.html", oauth_providers=oauth_providers)
        if not user.is_admin and not user.is_approved:
            flash("Your account is pending admin approval.", "error")
            return render_template("login.html", oauth_providers=oauth_providers)

        login_user(user.id, user.username)
        storage.update_user_login(user.id)
        # Force password change if set by admin
        if getattr(user, "must_change_password", False):
            session["must_change_password"] = True
            return redirect(url_for("auth.force_change_password"))
        next_url = _safe_next(request.args.get("next", ""), url_for("dashboard.index"))
        return redirect(next_url)

    return render_template("login.html", oauth_providers=oauth_providers)


# ── TOTP Setup ─────────────────────────────────────────────────────────────────


@auth_bp.route("/totp/setup", methods=["GET", "POST"])
def totp_setup():
    if not session.get("logged_in"):
        return redirect("/login")

    storage = get_storage()
    user_id = session["user_id"]
    username = session["username"]

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        secret = session.get("totp_setup_secret")

        if not secret:
            flash("Session expired. Please try again.", "error")
            return redirect(url_for("auth.totp_setup"))

        if not verify_totp(secret, code):
            flash("Invalid code. Please try again.", "error")
            qr = generate_totp_qr_base64(secret, username)
            return render_template("totp_setup.html", qr_code=qr, secret=secret)

        storage.enable_totp(user_id, secret)
        session.pop("totp_setup_secret", None)
        session.pop("must_setup_mfa", None)
        flash("Two-factor authentication enabled! Your account is now secure.", "success")
        return redirect(url_for("dashboard.index"))

    secret = generate_totp_secret()
    session["totp_setup_secret"] = secret
    qr = generate_totp_qr_base64(secret, username)
    return render_template("totp_setup.html", qr_code=qr, secret=secret)


# ── TOTP Verify ────────────────────────────────────────────────────────────────


@auth_bp.route("/totp/verify", methods=["GET", "POST"])
def totp_verify():
    pending_id = session.get("totp_pending_user_id")
    if not pending_id:
        return redirect("/login")

    storage = get_storage()

    if request.method == "POST":
        code = request.form.get("code", "").strip()
        user = storage.get_user_by_id(pending_id)

        if not user or not user.totp_secret:
            flash("Session expired.", "error")
            return redirect("/login")

        if not verify_totp(user.totp_secret, code):
            flash("Invalid code. Please try again.", "error")
            return render_template(
                "totp_verify.html", username=session.get("totp_pending_username")
            )

        login_user(user.id, user.username)
        storage.update_user_login(user.id)
        next_url = _safe_next(request.args.get("next", ""), url_for("dashboard.index"))
        return redirect(next_url)

    return render_template("totp_verify.html", username=session.get("totp_pending_username"))


# ── OAuth ──────────────────────────────────────────────────────────────────────


@auth_bp.route("/oauth/<provider>")
def oauth_redirect(provider):
    providers = get_oauth_providers()
    if provider not in providers:
        flash("OAuth provider not configured.", "error")
        return redirect("/login")

    p = providers[provider]
    state = secrets.token_urlsafe(32)
    session["oauth_state"] = state
    session["oauth_provider"] = provider

    callback_url = url_for("auth.oauth_callback", provider=provider, _external=True)
    params = {
        "client_id": p["client_id"],
        "redirect_uri": callback_url,
        "scope": p["scope"],
        "response_type": "code",
        "state": state,
    }
    return redirect(p["authorize_url"] + "?" + urlencode(params))


@auth_bp.route("/oauth/<provider>/callback")
def oauth_callback(provider):
    providers = get_oauth_providers()
    if provider not in providers:
        flash("Unknown OAuth provider.", "error")
        return redirect("/login")

    if request.args.get("state") != session.pop("oauth_state", None):
        flash("OAuth state mismatch. Please try again.", "error")
        return redirect("/login")

    code = request.args.get("code")
    if not code:
        flash("OAuth login failed — no code received.", "error")
        return redirect("/login")

    p = providers[provider]
    callback_url = url_for("auth.oauth_callback", provider=provider, _external=True)

    try:
        token_resp = http_requests.post(
            p["token_url"],
            data={
                "client_id": p["client_id"],
                "client_secret": p["client_secret"],
                "code": code,
                "redirect_uri": callback_url,
                "grant_type": "authorization_code",
            },
            headers={"Accept": "application/json"},
            timeout=10,
        )
        access_token = token_resp.json().get("access_token")
    except Exception as e:
        logger.error(f"OAuth token exchange failed: {e}")
        flash("OAuth login failed. Please try again.", "error")
        return redirect("/login")

    if not access_token:
        flash("OAuth login failed — no access token.", "error")
        return redirect("/login")

    # Apple sends user info in the ID token, not a userinfo endpoint
    if provider == "apple":
        import base64
        import json as _json
        id_token = token_resp.json().get("id_token", "")
        try:
            payload = id_token.split(".")[1]
            payload += "=" * (4 - len(payload) % 4)
            userinfo = _json.loads(base64.urlsafe_b64decode(payload))
        except Exception:
            userinfo = {}
    elif p.get("userinfo_url"):
        try:
            userinfo = http_requests.get(
                p["userinfo_url"],
                headers={"Authorization": f"Bearer {access_token}", "Accept": "application/json"},
                timeout=10,
            ).json()
        except Exception as e:
            logger.error(f"OAuth userinfo failed: {e}")
            flash("OAuth login failed — could not fetch user info.", "error")
            return redirect("/login")
    else:
        userinfo = {}

    if provider == "google":
        oauth_id = userinfo.get("sub")
        email = userinfo.get("email")
        username = email.split("@")[0] if email else f"google_{str(oauth_id)[:8]}"
    elif provider == "github":
        oauth_id = str(userinfo.get("id"))
        email = userinfo.get("email")
        username = userinfo.get("login") or f"github_{oauth_id[:8]}"
    elif provider == "microsoft":
        oauth_id = userinfo.get("id") or userinfo.get("sub")
        email = userinfo.get("mail") or userinfo.get("userPrincipalName") or userinfo.get("email")
        username = (email.split("@")[0] if email else None) or f"ms_{str(oauth_id)[:8]}"
    elif provider == "apple":
        oauth_id = userinfo.get("sub")
        email = userinfo.get("email")
        username = email.split("@")[0] if email else f"apple_{str(oauth_id)[:8]}"
    else:
        flash("Unknown provider.", "error")
        return redirect("/login")

    if not oauth_id:
        flash("Could not retrieve user identity from OAuth provider.", "error")
        return redirect("/login")

    storage = get_storage()

    if storage.count_users() == 0:
        flash("Please create a local admin account first.", "error")
        return redirect(url_for("auth.register"))

    user = storage.get_user_by_oauth(provider, oauth_id)
    if not user and email:
        user = storage.get_user_by_email(email)

    if not user:
        base_username = username
        counter = 1
        while storage.get_user_by_username(username):
            username = f"{base_username}{counter}"
            counter += 1

        user_id = storage.create_user(
            username=username,
            email=email,
            oauth_provider=provider,
            oauth_id=oauth_id,
            is_admin=False,
        )
        user = storage.get_user_by_id(user_id)

    login_user(user.id, user.username)
    storage.update_user_login(user.id)
    return redirect(url_for("dashboard.index"))



# ── Force Password Change ──────────────────────────────────────────────────────


@auth_bp.route("/force-change-password", methods=["GET", "POST"])
def force_change_password():
    if not session.get("logged_in"):
        return redirect("/login")

    if not session.get("must_change_password"):
        return redirect(url_for("dashboard.index"))

    storage = get_storage()
    user_id = session["user_id"]

    if request.method == "POST":
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")

        if new_pw != confirm:
            flash("Passwords do not match.", "error")
            return render_template("force_change_password.html")

        err = validate_password_strength(new_pw)
        if err:
            flash(err, "error")
            return render_template("force_change_password.html")

        storage.update_user_password(user_id, hash_password(new_pw))
        storage.set_must_change_password(user_id, False)
        session.pop("must_change_password", None)
        session["must_setup_mfa"] = True  # force MFA setup next
        flash("Password updated. Now set up two-factor authentication to continue.", "success")
        return redirect(url_for("auth.totp_setup"))

    return render_template("force_change_password.html")


# ── Logout ─────────────────────────────────────────────────────────────────────


@auth_bp.route("/logout")
def logout():
    logout_user()
    flash("You have been logged out.", "success")
    return redirect("/login")
