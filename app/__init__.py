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

        table_names = set(inspector.get_table_names())

        if "utilisateur" in table_names:
            columns = {col["name"] for col in inspector.get_columns("utilisateur")}
            if "created_at" not in columns:
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

        if "broadcast_notification" in table_names:
            columns = {col["name"] for col in inspector.get_columns("broadcast_notification")}

            if "emoji" not in columns:
                app.logger.info("Adding missing broadcast_notification.emoji column")
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            ALTER TABLE broadcast_notification
                            ADD COLUMN emoji VARCHAR(8) NOT NULL DEFAULT '⚠️'
                            """
                        )
                    )

            if "level" not in columns:
                app.logger.info("Adding missing broadcast_notification.level column")
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            ALTER TABLE broadcast_notification
                            ADD COLUMN level VARCHAR(20) NOT NULL DEFAULT 'warning'
                            """
                        )
                    )

        if "fiche_implique" in table_names:
            columns = {col["name"] for col in inspector.get_columns("fiche_implique")}

            if "type_fiche" not in columns:
                app.logger.info("Adding missing fiche_implique.type_fiche column")
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            ALTER TABLE fiche_implique
                            ADD COLUMN type_fiche VARCHAR(20) NOT NULL DEFAULT 'humain'
                            """
                        )
                    )
                    conn.execute(
                        text(
                            """
                            UPDATE fiche_implique
                            SET type_fiche = CASE WHEN est_animal IS TRUE THEN 'animal' ELSE 'humain' END
                            WHERE type_fiche IS NULL
                            """
                        )
                    )

            if "animal_espece" not in columns:
                app.logger.info("Adding missing fiche_implique.animal_espece column")
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            ALTER TABLE fiche_implique
                            ADD COLUMN animal_espece VARCHAR(120)
                            """
                        )
                    )

            if "animal_details" not in columns:
                app.logger.info("Adding missing fiche_implique.animal_details column")
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            ALTER TABLE fiche_implique
                            ADD COLUMN animal_details TEXT
                            """
                        )
                    )

            if "referent_humain_id" not in columns:
                app.logger.info("Adding missing fiche_implique.referent_humain_id column")
                with db.engine.begin() as conn:
                    conn.execute(
                        text(
                            """
                            ALTER TABLE fiche_implique
                            ADD COLUMN referent_humain_id INTEGER REFERENCES fiche_implique(id)
                            """
                        )
                    )


def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    # --- Config ---
    from config import config_by_name, ProductionConfig
    cfg_cls = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG", "prod"), ProductionConfig)
    app.config.from_object(cfg_cls)
    app.config.setdefault("BROADCAST_AUTO_CLEAR_SECONDS", 15)

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
    from .models import Utilisateur as UserModel, BroadcastNotification

    @login_manager.user_loader
    def load_user(user_id: str):
        try:
            return db.session.get(UserModel, int(user_id))
        except Exception:
            # Compat si la PK n'est pas un int
            return UserModel.query.get(user_id)

    @app.context_processor
    def inject_broadcast_banner():
        active = None
        try:
            from . import routes
            active = (
                BroadcastNotification.query.filter_by(is_active=True)
                .order_by(BroadcastNotification.created_at.desc())
                .first()
            )
        except Exception:
            active = None
        return {
            "active_broadcast": active,
            "broadcast_auto_clear_seconds": app.config.get("BROADCAST_AUTO_CLEAR_SECONDS", 15),
            "broadcast_allowed_emojis": getattr(routes, "BROADCAST_ALLOWED_EMOJIS", ["⚠️"]),
            "broadcast_allowed_levels": getattr(routes, "BROADCAST_ALLOWED_LEVELS", ["warning"]),
            "broadcast_default_emoji": getattr(routes, "BROADCAST_DEFAULT_EMOJI", "⚠️"),
            "broadcast_default_level": getattr(routes, "BROADCAST_DEFAULT_LEVEL", "warning"),
        }

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

    @app.errorhandler(404)
    def handle_not_found(e):
        return (
            render_template(
                "error_page.html",
                code=404,
                title="Page introuvable",
                message="La page demandée est introuvable ou n'existe plus.",
            ),
            404,
        )

    @app.errorhandler(500)
    def handle_internal_error(e):
        app.logger.exception("Unhandled error while processing a request")
        return (
            render_template(
                "error_page.html",
                code=500,
                title="Erreur interne",
                message="Une erreur inattendue est survenue. L'équipe technique a été alertée.",
            ),
            500,
        )

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
