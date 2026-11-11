import os
from pathlib import Path

from dotenv import load_dotenv

project_root = Path(__file__).resolve().parents[2]
backend_dir = Path(__file__).resolve().parents[1]
for env_path in (backend_dir / ".env", project_root / ".env"):
    if env_path.exists():
        load_dotenv(env_path, override=True)


def _csv_list(value: str | None, *fallback: str) -> list[str]:
    values = [item.strip() for item in (value or ",").split(",") if item.strip()]
    for item in fallback:
        if item.strip() and item.strip() not in values:
            values.append(item.strip())
    return values


class Settings:
    def __init__(self):
        self.PAYPAL_MODE = (os.getenv("PAYPAL_MODE") or "sandbox").strip().lower() or "sandbox"
        self.PAYPAL_CLIENT_ID = (os.getenv("PAYPAL_CLIENT_ID") or "").strip()
        self.PAYPAL_CLIENT_SECRET = (os.getenv("PAYPAL_CLIENT_SECRET") or "").strip()
        self.PAYPAL_LIVE_PAYOUTS_ENABLED = (os.getenv("PAYPAL_LIVE_PAYOUTS_ENABLED") or "false").strip().lower() == "true"

        if self.PAYPAL_MODE == "live":
            self.PAYPAL_API_BASE = (os.getenv("PAYPAL_API_BASE") or "https://api-m.paypal.com").strip() or "https://api-m.paypal.com"
            self.PAYPAL_WEB_BASE = (os.getenv("PAYPAL_WEB_BASE") or "https://www.paypal.com").strip() or "https://www.paypal.com"
        else:
            self.PAYPAL_API_BASE = (os.getenv("PAYPAL_API_BASE") or "https://api-m.sandbox.paypal.com").strip() or "https://api-m.sandbox.paypal.com"
            self.PAYPAL_WEB_BASE = (os.getenv("PAYPAL_WEB_BASE") or "https://www.sandbox.paypal.com").strip() or "https://www.sandbox.paypal.com"

        self.PAYPAL_WEBHOOK_ID = (os.getenv("PAYPAL_WEBHOOK_ID") or "").strip()
        self.DATABASE_URL = os.getenv(
            "DATABASE_URL",
            "sqlite:///./paypal_fraud_local.db",
        )
        self.APP_ENV = (os.getenv("APP_ENV") or "development").strip() or "development"
        self.ALLOW_LOCAL_DEV_UNAUTH = (os.getenv("ALLOW_LOCAL_DEV_UNAUTH") or "false").strip().lower() == "true"
        self.AUTH_SECRET_KEY = (os.getenv("AUTH_SECRET_KEY") or "").strip()
        self.DASHBOARD_AUTH_REQUIRED = str(os.getenv("DASHBOARD_AUTH_REQUIRED") or "").strip().lower()
        if self.DASHBOARD_AUTH_REQUIRED in {"true", "1", "yes", "on"}:
            self.DASHBOARD_AUTH_REQUIRED = True
        elif self.DASHBOARD_AUTH_REQUIRED in {"false", "0", "no", "off"}:
            self.DASHBOARD_AUTH_REQUIRED = False
        else:
            self.DASHBOARD_AUTH_REQUIRED = self.APP_ENV.lower() == "production"
        self.DASHBOARD_USERNAME = (os.getenv("DASHBOARD_USERNAME") or "").strip()
        self.DASHBOARD_PASSWORD = (os.getenv("DASHBOARD_PASSWORD") or "").strip()
        self.DASHBOARD_SESSION_COOKIE = (os.getenv("DASHBOARD_SESSION_COOKIE") or "dashboard_session").strip() or "dashboard_session"
        self.SESSION_TOKEN_TTL_MINUTES = max(5, int((os.getenv("SESSION_TOKEN_TTL_MINUTES") or "120").strip() or "120"))
        self.RATE_LIMIT_PER_MINUTE = max(5, int((os.getenv("RATE_LIMIT_PER_MINUTE") or "60").strip() or "60"))
        self.FRONTEND_URL = (os.getenv("FRONTEND_URL") or "http://localhost:5174").strip()
        self.BACKEND_URL = (os.getenv("BACKEND_URL") or "http://localhost:8000").strip()
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
