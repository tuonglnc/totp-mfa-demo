"""
app/routes/page_routes.py — HTML Page Serving Routes
"""

from flask import Blueprint, render_template, session, redirect, url_for

page_bp = Blueprint("pages", __name__)


def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user_id") or not session.get("authenticated"):
            return redirect(url_for("pages.login_page"))
        return f(*args, **kwargs)
    return decorated


@page_bp.route("/")
def index():
    if session.get("authenticated"):
        return redirect(url_for("pages.dashboard"))
    return redirect(url_for("pages.login_page"))


@page_bp.route("/login")
def login_page():
    if session.get("authenticated"):
        return redirect(url_for("pages.dashboard"))
    return render_template("login.html")


@page_bp.route("/register")
def register_page():
    if session.get("authenticated"):
        return redirect(url_for("pages.dashboard"))
    return render_template("register.html")


@page_bp.route("/verify-mfa")
def verify_mfa_page():
    return render_template("verify_totp.html")


@page_bp.route("/enroll-2fa")
def enroll_2fa_page():
    return render_template("enroll_2fa.html")


@page_bp.route("/dashboard")
@login_required
def dashboard():
    return render_template("dashboard.html")
