import os
import secrets

from decouple import config


class Config:
    """Application configuration with secure development defaults."""

    _configured_secret = config("SECRET_KEY", default="")
    _known_insecure_secrets = {"", "S#perS3crEt_007", "change-me", "secret"}
    ENV = config("APP_ENV", default="development").lower()

    if _configured_secret in _known_insecure_secrets:
        if ENV == "production":
            raise RuntimeError("Set a unique SECRET_KEY before running in production.")
        # Safe for local development; sessions are invalidated when the process restarts.
        SECRET_KEY = secrets.token_urlsafe(48)
    else:
        SECRET_KEY = _configured_secret

    SQLALCHEMY_DATABASE_URI = "sqlite:///" + os.path.join(os.path.dirname(__file__), "db.sqlite3")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = ENV == "production"
    REMEMBER_COOKIE_HTTPONLY = True
    REMEMBER_COOKIE_SECURE = ENV == "production"
    PERMANENT_SESSION_LIFETIME = 1800
    MAX_CONTENT_LENGTH = 1024 * 1024
