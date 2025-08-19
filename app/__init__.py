from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from .models import User  # noqa
import os

db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
limiter = Limiter(key_func=get_remote_address, storage_uri="memory://")

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

    # Register blueprints (keep existing routes)
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # Example: add a health check
    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    # Rate limiter
    limiter.init_app(app)

    # Ensure default admin/admin exists (user requested); create only if missing
    with app.app_context():
        try:
            db.create_all()
            if not User.query.filter_by(username="admin").first():
                admin = User(username="admin", is_admin=True)
                try:
                    admin.set_password("admin")
                except Exception:
                    # fallback field name
                    if hasattr(admin, "password"):
                        admin.password = "admin"
                db.session.add(admin)
                db.session.commit()
        except Exception as e:
            app.logger.warning("Database init skipped or failed: %s", e)

    return app
