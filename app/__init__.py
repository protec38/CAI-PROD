# app/__init__.py
import os
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError

from .extensions import db, login_manager, csrf, limiter


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    # --- Config ---
    from config import config_by_name, ProductionConfig
    cfg_cls = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg_cls)

    # ===== CSRF (Flask-WTF) =====
    # Seules les méthodes d'écriture sont protégées
    app.config["WTF_CSRF_METHODS"] = ["POST", "PUT", "PATCH", "DELETE"]
    # Autoriser le header que l'on envoie côté front (X-CSRFToken)
    app.config["WTF_CSRF_HEADERS"] = ["X-CSRFToken", "X-CSRF-Token"]

    # --- Proxy / HTTPS / Sécurité ---
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # IMPORTANT : autoriser le JS inline (dashboard) et les CDN utilisés
    csp = {
    "default-src": "'self'",
    "img-src": "'self' data:",
    "style-src": "'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com 'unsafe-inline'",
    "font-src": "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:",
    # ✅ autorise les <script> inline de tes templates + cdnjs si tu l’utilises
    "script-src": "'self' https://cdnjs.cloudflare.com 'unsafe-inline'",
    # ✅ autorise fetch/XHR vers ton backend
    "connect-src": "'self'",
    }


    Talisman(
        app,
        content_security_policy=csp,
        force_https=bool(int(os.getenv("FORCE_HTTPS", "1"))),
    )

    # --- Extensions ---
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # --- Flask-Login config ---
    login_manager.login_view = "main_bp.login"
    login_manager.login_message_category = "info"

    # --- Loader utilisateur ---
    from .models import Utilisateur as UserModel

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return db.session.get(UserModel, int(user_id))
        except Exception:
            return UserModel.query.get(user_id)

    # --- Gestion CSRF (page d’erreur claire) ---
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template("csrf_error.html", reason=e.description), 400

    # --- Hook audit ---
    @app.before_request
    def before_log_mutations():
        from flask import request
        from .audit import log_action
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.path.startswith("/static"):
            ep = request.endpoint or request.path
            log_action(f"HTTP {request.method} {ep}")

    # --- Blueprints ---
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # --- Healthcheck ---
    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app
