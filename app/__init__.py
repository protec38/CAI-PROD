# app/__init__.py
import os
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError

from .extensions import db, login_manager, csrf, limiter
from sqlalchemy import inspect, text


def _ensure_database_schema(app: Flask) -> None:
    """Ensure critical columns exist when the app boots.

    Older deployments might miss newer columns because ``db.create_all``
    does not alter existing tables.  We patch the schema at runtime so the
    application can start even on an outdated database.
    """

    with app.app_context():
        try:
            inspector = inspect(db.engine)
        except Exception as exc:  # pragma: no cover - safety net for startup
            app.logger.warning("Unable to inspect database schema: %s", exc)
            return

        if "utilisateur" not in inspector.get_table_names():
            return

        columns = {col["name"] for col in inspector.get_columns("utilisateur")}
        if "created_at" in columns:
            return

        app.logger.info("Adding missing utilisateur.created_at column")
        with db.engine.begin() as conn:
            conn.execute(
                text(
                    """
                    ALTER TABLE utilisateur
                    ADD COLUMN created_at TIMESTAMP WITHOUT TIME ZONE
                    DEFAULT (NOW() AT TIME ZONE 'UTC')
                    """
                )
            )
            conn.execute(
                text(
                    """
                    UPDATE utilisateur
                    SET created_at = NOW() AT TIME ZONE 'UTC'
                    WHERE created_at IS NULL
                    """
                )
            )
            conn.execute(
                text(
                    "ALTER TABLE utilisateur ALTER COLUMN created_at SET NOT NULL"
                )
            )
            conn.execute(
                text(
                    """
                    CREATE INDEX IF NOT EXISTS ix_utilisateur_created_at
                    ON utilisateur (created_at)
                    """
                )
            )


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    # --- Config ---
    from config import config_by_name, ProductionConfig
    cfg_cls = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg_cls)

    # ===== CSRF (Flask-WTF) =====
    # Seules les méthodes d'écriture sont protégées
    app.config["WTF_CSRF_METHODS"] = ["POST", "PUT", "PATCH", "DELETE"]
    # Autoriser le header que l'on envoie côté front (X-CSRFToken)
    app.config["WTF_CSRF_HEADERS"] = ["X-CSRFToken", "X-CSRF-Token"]

    # --- Proxy / HTTPS / Sécurité ---
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)

    # IMPORTANT : autoriser le JS inline (dashboard) et les CDN utilisés
    csp = {
        "default-src": "'self'",
        "img-src": "'self' data:",
        "style-src": "'self' https://fonts.googleapis.com https://cdnjs.cloudflare.com 'unsafe-inline'",
        "font-src": "'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com data:",
        # ✅ autorise les <script> inline de tes templates + cdnjs si tu l’utilises
        "script-src": "'self' https://cdnjs.cloudflare.com 'unsafe-inline'",
        # ✅ autorise fetch/XHR vers ton backend
        "connect-src": "'self'",
    }

    Talisman(
        app,
        content_security_policy=csp,
        force_https=bool(int(os.getenv("FORCE_HTTPS", "1"))),
    )

    # --- Extensions ---
    db.init_app(app)
    _ensure_database_schema(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # --- Flask-Login config ---
    # NOTE : conserve l'endpoint tel que dans ton code actuel.
    login_manager.login_view = "main_bp.login"
    login_manager.login_message_category = "info"

    # --- Loader utilisateur ---
    from .models import Utilisateur as UserModel

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return db.session.get(UserModel, int(user_id))
        except Exception:
            # Compat si la PK n'est pas un int
            return UserModel.query.get(user_id)

    # --- Filtres Jinja (fr_datetime / fr_date / fr_time) ---
    # Assure-toi d'avoir créé app/filters.py avec les fonctions fr_datetime, fr_date, fr_time
    from . import filters as jfilters
    app.add_template_filter(jfilters.fr_datetime, name="fr_datetime")
    app.add_template_filter(jfilters.fr_date,     name="fr_date")
    app.add_template_filter(jfilters.fr_time,     name="fr_time")
    app.add_template_filter(jfilters.age_in_years, name="age")
    app.add_template_filter(jfilters.humanize_timedelta, name="humanize_timedelta")

    # --- Gestion CSRF (page d’erreur claire) ---
    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template("csrf_error.html", reason=e.description), 400

    # --- Hook audit ---
    @app.before_request
    def before_log_mutations():
        from flask import request
        from .audit import log_action
        if request.method in {"POST", "PUT", "PATCH", "DELETE"} and not request.path.startswith("/static"):
            ep = request.endpoint or request.path
            log_action(f"HTTP {request.method} {ep}")

    # --- Blueprints ---
    from .routes import main_bp
    app.register_blueprint(main_bp)

    # --- Healthcheck ---
    @app.route("/healthz")
    def healthz():
        return {"status": "ok"}, 200

    return app
