import os
from datetime import timedelta
from pathlib import Path

_legacy_sqlite = Path(__file__).resolve().parent / "instance" / "instance" / "cai.db"

class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or (
        "sqlite:///instance/cai.db" if _legacy_sqlite.is_file() else "sqlite:///cai.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # Safe defaults for Postgres connection pooling
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_size": 10,
        "max_overflow": 20,
        "pool_pre_ping": True,
        "pool_recycle": 1800,
    }

    # Cookies sécurisés
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    REMEMBER_COOKIE_SECURE = True
    REMEMBER_COOKIE_SAMESITE = "Lax"
    PERMANENT_SESSION_LIFETIME = timedelta(hours=8)

    # CSRF uniquement sur méthodes mutantes
    WTF_CSRF_ENABLED = True
    WTF_CSRF_METHODS = ["POST","PUT","PATCH","DELETE"]
    WTF_CSRF_CHECK_DEFAULT = True
    WTF_CSRF_SSL_STRICT = False
    WTF_CSRF_TIME_LIMIT = 60*60*8
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024
    RATELIMIT_STORAGE_URI = os.environ.get("REDIS_URL", "redis://redis:6379/0")
    TRUSTED_PROXY_COUNT = int(os.environ.get("TRUSTED_PROXY_COUNT", "0"))
    FORCE_HTTPS = os.environ.get("FORCE_HTTPS", "1").lower() in {"1", "true", "yes"}

class DevelopmentConfig(BaseConfig):
    DEBUG = True
    SESSION_COOKIE_SECURE = False
    REMEMBER_COOKIE_SECURE = False
    FORCE_HTTPS = False
    RATELIMIT_STORAGE_URI = "memory://"

class ProductionConfig(BaseConfig):
    DEBUG = False
    PREFERRED_URL_SCHEME = "https"

config_by_name = {"dev": DevelopmentConfig, "prod": ProductionConfig}
