import os
from pathlib import Path

from dotenv import load_dotenv

project_root = Path(__file__).resolve().parents[2]
load_dotenv(project_root / ".env")


def _csv_list(value: str | None, *fallback: str) -> list[str]:
    values = [item.strip() for item in (value or ",").split(",") if item.strip()]
    for item in fallback:
        if item.strip() and item.strip() not in values:
            values.append(item.strip())
    return values


class Settings:
    def __init__(self):
        self.PAYPAL_MODE = os.getenv("PAYPAL_MODE", "sandbox")
        self.PAYPAL_CLIENT_ID = os.getenv("PAYPAL_CLIENT_ID", "")
        self.PAYPAL_CLIENT_SECRET = os.getenv("PAYPAL_CLIENT_SECRET", "")
        self.PAYPAL_API_BASE = os.getenv("PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
        self.PAYPAL_WEB_BASE = os.getenv("PAYPAL_WEB_BASE", "https://www.sandbox.paypal.com")
        self.PAYPAL_WEBHOOK_ID = os.getenv("PAYPAL_WEBHOOK_ID", "")
        self.DATABASE_URL = os.getenv(
            "DATABASE_URL",
            "sqlite:///./paypal_fraud_local.db",
        )
        self.APP_ENV = os.getenv("APP_ENV", "development")
        self.ALLOW_LOCAL_DEV_UNAUTH = os.getenv("ALLOW_LOCAL_DEV_UNAUTH", "true").lower() == "true"
        self.AUTH_SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "dev-secret-change-me")
        self.DASHBOARD_USERNAME = os.getenv("DASHBOARD_USERNAME", "admin")
        self.DASHBOARD_PASSWORD = os.getenv("DASHBOARD_PASSWORD", "admin123")
        self.SESSION_TOKEN_TTL_MINUTES = max(5, int(os.getenv("SESSION_TOKEN_TTL_MINUTES", "120")))
        self.RATE_LIMIT_PER_MINUTE = max(5, int(os.getenv("RATE_LIMIT_PER_MINUTE", "60")))
        self.FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:5174")
        self.BACKEND_URL = os.getenv("BACKEND_URL", "http://localhost:8000")
        self.CORS_ALLOWED_ORIGINS = _csv_list(
            os.getenv("CORS_ALLOWED_ORIGINS"),
            self.FRONTEND_URL,
            "http://localhost:5173",
            "http://127.0.0.1:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5174",
        )
        self.SARVAM_API_KEY = os.getenv("SARVAM_API_KEY", "")
        self.SARVAM_MODEL = os.getenv("SARVAM_MODEL", "sarvam-105b")
        self.SARVAM_API_BASE = os.getenv("SARVAM_API_BASE", "https://api.sarvam.ai")


settings = Settings()
