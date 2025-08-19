import os
from flask import Flask
from flask_talisman import Talisman
from .extensions import db, login_manager, csrf, limiter

def create_app(config_name: str | None = None):
    from config import config_by_name, ProductionConfig  # local import to avoid early eval
    app = Flask(__name__)
    cfg = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg)

    # Init extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    Talisman(app, content_security_policy=None)
    limiter.init_app(app)

    # Blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # Healthcheck
    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    # Create DB tables and ensure admin/admin
    with app.app_context():
        from . import models  # ensure models are registered
        try:
            db.create_all()
            from .models import User
            if not User.query.filter_by(username="admin").first():
                admin = User(username="admin", is_admin=True)
                # prefer set_password if exists
                if hasattr(admin, "set_password"):
                    admin.set_password("admin")
                else:
                    setattr(admin, "password", "admin")
                db.session.add(admin)
                db.session.commit()
        except Exception as e:
            app.logger.warning("Database init skipped or failed: %s", e)

    return app
