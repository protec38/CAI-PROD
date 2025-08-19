import os
from flask import Flask
from flask_talisman import Talisman
from werkzeug.middleware.proxy_fix import ProxyFix
from .extensions import db, login_manager, csrf, limiter

def create_app(config_name: str | None = None):
    \1
    # Trust X-Forwarded-* from the reverse proxy
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
# Config
    from config import config_by_name, ProductionConfig
    cfg = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg)

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    Talisman(app, content_security_policy=None, force_https=(os.getenv('FORCE_HTTPS','1')=='1'))
    limiter.init_app(app)

    # Blueprints
    try:
        from .routes import main_bp
        app.register_blueprint(main_bp)
    except Exception as e:
        app.logger.error("Failed to register blueprint: %s", e)
        raise

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app
