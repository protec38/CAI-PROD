import os, time
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
    from .routes import main_bp
    app.register_blueprint(main_bp)

    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    # Database init with simple retry (handles DB not ready yet)
    from sqlalchemy import text
    max_tries = int(os.environ.get("DB_INIT_MAX_TRIES", "20"))
    delay = float(os.environ.get("DB_INIT_DELAY", "1.0"))

    with app.app_context():
            pass  # DB init handled by init task

        return app
