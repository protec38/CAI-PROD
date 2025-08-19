from flask import render_template, request, redirect, url_for, flash, session, current_app
from collections import defaultdict
import time

from app.models import db, Utilisateur
from app.blueprints.decorators import login_required

# Anti bruteforce simple côté mémoire (par IP)
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

            # Interdire admin/admin en prod si configuré
            if (
                current_app.config.get("DISABLE_DEFAULT_ADMIN_LOGIN", True)
                and username == "admin"
                and password == "admin"
                and not current_app.config.get("DEBUG", False)
            ):
                _add_attempt(ip)
                flash("Identifiants par défaut désactivés. Définissez ADMIN_PASSWORD ou changez le mot de passe.", "danger")
                return render_template("login.html")

            user = Utilisateur.query.filter_by(nom_utilisateur=username).first()

            if user and user.check_password(password):
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
