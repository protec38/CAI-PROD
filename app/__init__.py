import os
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from .extensions import db, login_manager, csrf, limiter

def create_app(config_name: str | None = None):
    app = Flask(__name__)

    # Load config
    from config import config_by_name, ProductionConfig
    cfg = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg)

    # Respect reverse proxy headers (X-Forwarded-*)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # Security headers; HTTPS forcing can be disabled via env if behind proxy misconfigured
    force_https = os.getenv("FORCE_HTTPS", "0") == "1"
    Talisman(app, content_security_policy=None, force_https=force_https)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Register blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app
