import os
from flask import Flask, render_template
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFError

from .extensions import db, login_manager, csrf, limiter

def create_app(config_name: str | None = None) -> Flask:
    app = Flask(__name__)

    from config import config_by_name, ProductionConfig
    cfg_cls = config_by_name.get(config_name or os.environ.get("FLASK_CONFIG","prod"), ProductionConfig)
    app.config.from_object(cfg_cls)

    # Proxy + HTTPS
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1, x_prefix=1)
    Talisman(app, content_security_policy=None, force_https=(os.getenv("FORCE_HTTPS","0")=="1"))

    # Extensions
    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # Flask-Login config
    login_manager.login_view = "main_bp.login"
    login_manager.login_message_category = "info"

    # Models import after init
    try:
        from .models import Utilisateur as UserModel
    except Exception:
        try:
            from .models import User as UserModel  # type: ignore
        except Exception:
            UserModel = None  # type: ignore

    @login_manager.user_loader
    def load_user(user_id: str):
        if UserModel is None:
            return None
        try:
            return db.session.get(UserModel, int(user_id))
        except Exception:
            try:
                return db.session.get(UserModel, user_id)
            except Exception:
                try:
                    return UserModel.query.get(user_id)
                except Exception:
                    return None

    @app.errorhandler(CSRFError)
    def handle_csrf_error(e):
        return render_template("csrf_error.html", reason=e.description), 400

    # Blueprints
    from .routes import main_bp
    app.register_blueprint(main_bp)

    @app.route("/healthz")
    def healthz():
        return {"status":"ok"}, 200

    return app
