import os
from flask import Flask
from flask_talisman import Talisman
from .extensions import db, login_manager, csrf, limiter

def create_app(config_name: str | None = None):
    app = Flask(__name__)

    # Config
    from config import config_by_name, ProductionConfig
    cfg = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg)

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    Talisman(app, content_security_policy=None)
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
