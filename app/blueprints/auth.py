from flask import render_template, request, redirect, url_for, flash, session, current_app
from app.models import db, Utilisateur
from app.__init__ import bcrypt
from app.blueprints.decorators import login_required, role_required, event_member_required
from collections import defaultdict
import time

# Basic in-memory rate limiter for login attempts per IP
_LOGIN_ATTEMPTS = defaultdict(list)
_MAX_ATTEMPTS = 10
_WINDOW_SEC = 900  # 15 min

def _rate_limited(ip: str) -> bool:
    now = time.time()
    attempts = [t for t in _LOGIN_ATTEMPTS[ip] if now - t < _WINDOW_SEC]
    _LOGIN_ATTEMPTS[ip] = attempts
    return len(attempts) >= _MAX_ATTEMPTS

def _add_attempt(ip: str):
    _LOGIN_ATTEMPTS[ip].append(time.time())

def register(bp):
    @bp.route("/", methods=["GET", "POST"], endpoint="login")
    def login():
        if request.method == "POST":
            ip = request.headers.get("X-Forwarded-For", request.remote_addr or "")
            if _rate_limited(ip):
                flash("Trop de tentatives. Réessayez plus tard.", "danger")
                return render_template("login.html")

            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            user = Utilisateur.query.filter_by(username=username).first()

            # Block default admin/admin when configured to do so
            if (
                current_app.config.get("DISABLE_DEFAULT_ADMIN_LOGIN", True)
                and username == "admin"
                and password == "admin"
                and not current_app.config.get("DEBUG", False)
            ):
                _add_attempt(ip)
                flash("Identifiants par défaut désactivés. Définissez ADMIN_PASSWORD ou changez le mot de passe.", "danger")
                return render_template("login.html")

            if user and bcrypt.check_password_hash(user.password_hash, password):
                session["user_id"] = user.id
                session.permanent = True
                flash("Connexion réussie.", "success")
                return redirect(url_for("main_bp.dashboard"))
            else:
                _add_attempt(ip)
                flash("Identifiants invalides.", "danger")
        return render_template("login.html")

    @bp.route("/logout", methods=["POST"], endpoint="logout")
    @login_required
    def logout():
        session.clear()
        flash("Déconnecté.", "info")
        return redirect(url_for("main_bp.login"))
