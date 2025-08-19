import os
from datetime import timedelta

class Config:
    # --- Secret Key ---
    SECRET_KEY = os.environ.get("SECRET_KEY", "CHANGE_ME_DEV_ONLY")
    DEBUG = os.environ.get("FLASK_DEBUG", "0") == "1"

    # --- Database ---
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL", "sqlite:///../db/cai.db")
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # --- CSRF (Flask-WTF) ---
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = None  # tokens don't expire during a session
    WTF_CSRF_METHODS = ["POST", "PUT", "PATCH", "DELETE"]
    WTF_CSRF_SSL_STRICT = False

    # --- Session / Cookies ---
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "0") == "1"
    REMEMBER_COOKIE_HTTPONLY = True
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # --- Security Headers ---
    # If you serve assets from a CDN, extend the CSP accordingly.
    CONTENT_SECURITY_POLICY = "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'"

    # --- Admin bootstrap ---
    ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
    ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", None)  # if None, login with admin/admin is refused in prod
    DISABLE_DEFAULT_ADMIN_LOGIN = os.environ.get("DISABLE_DEFAULT_ADMIN_LOGIN", "1") == "1"  # block 'admin'/'admin' by default

def require_secure_secret_key(cfg: "Config"):
    """
    Raise loudly if running without a secure SECRET_KEY in non-debug contexts.
    """
    if not cfg.DEBUG and (not cfg.SECRET_KEY or cfg.SECRET_KEY == "CHANGE_ME_DEV_ONLY"):
        raise RuntimeError("SECURITY: SECRET_KEY must be set via environment in production.")
