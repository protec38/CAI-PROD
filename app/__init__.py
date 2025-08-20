import os
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError
from .extensions import db, login_manager, csrf, limiter

def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    # ---- Config
    from config import config_by_name, ProductionConfig
    cfg = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg)

    # ---- Proxy/HTTPS
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    Talisman(app, content_security_policy=None, force_https=(os.getenv("FORCE_HTTPS", "0") == "1"))

    # ---- CSRF : borne aux méthodes mutantes
    app.config.setdefault("WTF_CSRF_ENABLED", True)
    app.config.setdefault("WTF_CSRF_METHODS", ["POST", "PUT", "PATCH", "DELETE"])
    app.config.setdefault("WTF_CSRF_CHECK_DEFAULT", False)
    app.config.setdefault("WTF_CSRF_SSL_STRICT", False)
    app.config.setdefault("WTF_CSRF_TIME_LIMIT", 60 * 60 * 8)

    # ---- Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # ---- Flask-Login
    login_manager.login_view = "main_bp.login"
    login_manager.login_message_category = "info"

    # ---- Blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # ---- Anti-bruteforce sur la vue login, sans modifier routes.py
    #     (si la vue existe sous cet endpoint)
    try:
        view = app.view_functions.get("main_bp.login")
        if view:
            limiter.limit("5/minute")(view)
    except Exception:
        pass

    # ---- Erreur CSRF propre
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        try:
            return render_template("csrf_error.html", reason=e.description), 400
        except Exception:
            return {"error": "CSRF error", "detail": e.description}, 400

    # ---- Santé
    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app
