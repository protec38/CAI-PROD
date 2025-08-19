import os
from datetime import timedelta

class BaseConfig:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret")
    SQLALCHEMY_DATABASE_URI = os.environ.get("DATABASE_URL") or "sqlite:///instance/cai.db"
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
    WTF_CSRF_CHECK_DEFAULT = False
    WTF_CSRF_SSL_STRICT = False
    WTF_CSRF_TIME_LIMIT = 60*60*8

class DevelopmentConfig(BaseConfig):
    DEBUG = True

class ProductionConfig(BaseConfig):
    DEBUG = False
    PREFERRED_URL_SCHEME = "https"

config_by_name = {"dev": DevelopmentConfig, "prod": ProductionConfig}
