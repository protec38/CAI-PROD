from flask import Flask
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf

from config import Config, require_secure_secret_key
from .models import db  # IMPORTANT : models.py doit définir `db = SQLAlchemy()`

csrf = CSRFProtect()
migrate = Migrate()

def create_app():
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(Config)

    # Stop si SECRET_KEY non sécure hors debug
    require_secure_secret_key(Config)

    # Init extensions
    db.init_app(app)
    csrf.init_app(app)
    migrate.init_app(app, db)

    # Jinja: expose csrf_token() pour les formulaires
    @app.context_processor
    def inject_csrf_token():
        return dict(csrf_token=generate_csrf)

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

    # Register blueprints (conserve les endpoints main_bp.*)
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # Seed admin si absent et ADMIN_PASSWORD défini
    with app.app_context():
        from .models import Utilisateur
        admin = Utilisateur.query.filter_by(
            nom_utilisateur=app.config.get("ADMIN_USERNAME", "admin")
        ).first()
        if not admin and app.config.get("ADMIN_PASSWORD"):
            admin = Utilisateur(
                nom_utilisateur=app.config["ADMIN_USERNAME"],
                role="admin",
                is_admin=True,
                actif=True,
            )
            admin.set_password(app.config["ADMIN_PASSWORD"])
            db.session.add(admin)
            db.session.commit()

    return app
