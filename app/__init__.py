from flask import Flask
from flask_migrate import Migrate
from flask_wtf import CSRFProtect
from flask_wtf.csrf import generate_csrf
import os

from config import Config, require_secure_secret_key
from .models import db  # models.py doit définir: from flask_sqlalchemy import SQLAlchemy ; db = SQLAlchemy()

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

    # En-têtes de sécurité
    @app.after_request
    def set_security_headers(resp):
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        csp = app.config.get("CONTENT_SECURITY_POLICY")
        if csp:
            resp.headers.setdefault("Content-Security-Policy", csp)
        return resp

    # --- CRÉATION DES TABLES AVANT TOUT USAGE DE LA DB ---
    with app.app_context():
        # S'assurer que le dossier SQLite existe (../db par rapport à app/)
        uri = app.config.get("SQLALCHEMY_DATABASE_URI", "")
        if uri.startswith("sqlite:///"):
            db_dir = os.path.abspath(os.path.join(app.root_path, "..", "db"))
            os.makedirs(db_dir, exist_ok=True)

        # Idempotent: crée toutes les tables qui manquent
        db.create_all()

        # Seed admin si absent ET mot de passe fourni
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
            # ton modèle doit avoir set_password / check_password
            admin.set_password(app.config["ADMIN_PASSWORD"])
            db.session.add(admin)
            db.session.commit()

    # Enregistrer le blueprint principal (conserve les endpoints main_bp.*)
    from .routes import main_bp
    app.register_blueprint(main_bp)

    return app
