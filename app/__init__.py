from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_bcrypt import Bcrypt
from flask_wtf import CSRFProtect
from .models import db  # type: ignore
from .backup_utils import *  # noqa
from config import Config, require_secure_secret_key

bcrypt = Bcrypt()
csrf = CSRFProtect()
migrate = Migrate()

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(Config)

    # Hard fail if SECRET_KEY is not secure (outside debug)
    require_secure_secret_key(Config)

    # Init extensions
    db.init_app(app)
    bcrypt.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    # Security headers
    @app.after_request
    def set_security_headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        csp = app.config.get("CONTENT_SECURITY_POLICY")
        if csp:
            resp.headers.setdefault("Content-Security-Policy", csp)
        return resp

    # Register blueprints
    from .routes import main_bp  # preserve compatibility of endpoint names
    app.register_blueprint(main_bp)

    # Seed admin if missing and an ADMIN_PASSWORD is provided
    with app.app_context():
        from .models import Utilisateur
        admin = Utilisateur.query.filter_by(username=app.config.get("ADMIN_USERNAME", "admin")).first()
        if not admin and app.config.get("ADMIN_PASSWORD"):
            pwd_hash = bcrypt.generate_password_hash(app.config["ADMIN_PASSWORD"]).decode("utf-8")
            admin = Utilisateur(
                username=app.config["ADMIN_USERNAME"],
                role="admin",
                password_hash=pwd_hash,
            )
            db.session.add(admin)
            db.session.commit()

    return app
