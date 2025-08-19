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
        for attempt in range(1, max_tries + 1):
            try:
                # Touch the DB to confirm connectivity
                db.session.execute(text("SELECT 1"))
                db.create_all()
                # Import models after init to avoid circular imports
                from .models import User  # noqa
                # Ensure admin/admin exists if missing
                if not User.query.filter_by(username="admin").first():
                    admin = User(username="admin", is_admin=True)
                    try:
                        admin.set_password("admin")
                    except Exception:
                        if hasattr(admin, "password"):
                            admin.password = "admin"
                    db.session.add(admin)
                    db.session.commit()
                break
            except Exception as e:
                if attempt == max_tries:
                    app.logger.warning("Database init failed after %s attempts: %s", attempt, e)
                    break
                app.logger.info("DB not ready (attempt %s/%s): %s; retrying in %.1fs", attempt, max_tries, e, delay)
                time.sleep(delay)

    return app
