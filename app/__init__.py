# app/__init__.py
import os
from flask import Flask
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman

# Extensions centralisées (évite les imports circulaires)
from .extensions import db, login_manager, csrf, limiter


def create_app(config_name: str | None = None) -> Flask:
    """
    Factory principale de l'application.
    - Charge la config (dev/prod) depuis FLASK_CONFIG ou paramètre.
    - Initialise les extensions (DB, Login, CSRF, Limiter).
    - Configure ProxyFix + Talisman (HTTPS pilotable via FORCE_HTTPS).
    - Enregistre les blueprints.
    - Expose /healthz.
    """
    app = Flask(__name__)

    # -------------------------
    # Configuration
    # -------------------------
    from config import config_by_name, ProductionConfig

    cfg_cls = config_by_name.get(
        config_name or os.environ.get("FLASK_CONFIG", "prod"),
        ProductionConfig,
    )
    app.config.from_object(cfg_cls)

    # -------------------------
    # Proxy / HTTPS
    # -------------------------
    # Fait confiance aux en-têtes X-Forwarded-* du reverse-proxy (Nginx/Traefik/Cloudflare)
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # Force HTTPS si demandé (peut être désactivé en dev ou si le proxy ne passe pas X-Forwarded-Proto)
    force_https = os.getenv("FORCE_HTTPS", "0") == "1"
    Talisman(app, content_security_policy=None, force_https=force_https)

    # -------------------------
    # Extensions
    # -------------------------
    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = "main_bp.login"
    login_manager.login_message_category = "info"
    csrf.init_app(app)
    limiter.init_app(app)

    # Page de login par défaut (adapter si l'endpoint diffère)
    login_manager.login_view = "main.login"
    login_manager.login_message_category = "info"

    # -------------------------
    # Flask-Login: user_loader
    # -------------------------
    # On importe les modèles *après* l'init des extensions pour éviter tout import circulaire.
    try:
        from .models import Utilisateur as UserModel
    except Exception:
        # Repli si le modèle s'appelle "User"
        from .models import User as UserModel  # type: ignore

    @login_manager.user_loader
    def load_user(user_id: str):
        """
        Récupère un utilisateur à partir de son ID stocké en session.
        Compatible SQLAlchemy 2.x (db.session.get), repli sur query.get si nécessaire.
        """
        # Si ta PK n'est pas un entier (UUID/str), lève l'exception et on tente la version str.
        try:
            return db.session.get(UserModel, int(user_id))
        except Exception:
            try:
                return db.session.get(UserModel, user_id)
            except Exception:
                # Compat ancien Flask-SQLAlchemy
                return UserModel.query.get(user_id)

    # -------------------------
    # Blueprints
    # -------------------------
    from .routes import main_bp  # importe *après* init extensions
    app.register_blueprint(main_bp)

    # -------------------------
    # Healthcheck
    # -------------------------
    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app
