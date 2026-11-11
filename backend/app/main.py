from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .config import settings
from .db import Base, SessionLocal, ensure_database_schema, engine, get_db
from .fraud import create_ml_fraud_model, generate_fraud_alerts, score_transaction, summarize_ml_scores
from .models import FraudAlert, PayPalTransactionRecord, PayPalWebhookEvent, SessionToken, User
from .paypal import (
    PayPalConfigError,
    PayPalPermissionError,
    fetch_account_balance,
    fetch_capture_details,
    fetch_order_details,
    fetch_payout_batch_details,
    fetch_transaction_history,
    create_checkout_order,
    create_payout,
    capture_checkout_order,
    normalize_account_balance,
)
from .sarvam import generate_ai_explanation

app = FastAPI(title="PayPal Fraud Detection & Payment Finder", version="1.0.0")

_RATE_LIMIT_WINDOW_SECONDS = 60
_RATE_LIMIT_BUCKETS: dict[str, deque[float]] = defaultdict(deque)
_SUPPORTED_WEBHOOK_EVENTS = {
    "PAYMENT.CAPTURE.COMPLETED",
    "PAYMENT.CAPTURE.DENIED",
    "PAYMENT.CAPTURE.REFUNDED",
}

_SENSITIVE_ROUTE_PREFIXES = (
    "/api/paypal/transactions",
    "/api/paypal/alerts",
    "/api/paypal/webhook-events",
    "/api/paypal/webhooks",
    "/api/paypal/balance",
    "/api/paypal/import",
    "/api/paypal/orders",
    "/api/paypal/payouts",
    "/api/paypal/captures",
    "/api/dashboard",
)


class DashboardAuthRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=255)
    password: str = Field(..., min_length=1, max_length=255)


class CreateOrderRequest(BaseModel):
    amount: str = Field(
        default="1.00",
        pattern=r"^\d+(\.\d{1,2})?$"
    )
    currency: str = Field(
        default="USD",
        min_length=3,
        max_length=3
    )


class PayoutRequest(BaseModel):
    recipient_email: str = Field(..., min_length=3, max_length=255)
    amount: str = Field(default="1.00", pattern=r"^\d+(\.\d{1,2})?$")
    currency: str = Field(default="USD", min_length=3, max_length=3)
    note: str = Field(default="PayPal payout from the dashboard", max_length=200)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        client_ip = request.client.host if request.client else "unknown"
        now = time.monotonic()
        bucket = _RATE_LIMIT_BUCKETS[client_ip]
        while bucket and (now - bucket[0]) > _RATE_LIMIT_WINDOW_SECONDS:
            bucket.popleft()
        if len(bucket) >= settings.RATE_LIMIT_PER_MINUTE:
            return JSONResponse(
                status_code=429,
                content={"detail": "Too many requests. Please wait a moment and try again."},
            )
        bucket.append(now)
    return await call_next(request)


app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def startup_event():
    try:
        ensure_database_schema(engine)
        Base.metadata.create_all(bind=engine)
        ensure_database_schema(engine)
    except Exception as exc:  # pragma: no cover - depends on local database availability
        print(f"Database unavailable during startup; API remains available in degraded mode: {exc}")


def _dashboard_cookie_options() -> dict[str, Any]:
    return {
        "httponly": True,
        "samesite": "lax",
        "secure": settings.APP_ENV.lower() == "production",
        "path": "/",
    }


def _hash_session_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _webhook_headers(request: Request) -> dict[str, str]:
    headers: dict[str, str] = {}
    for key, value in request.headers.items():
        normalized = key.strip().lower()
        if not normalized.startswith("paypal-"):
            continue
        if normalized == "paypal-auth-alg":
            normalized = "paypal-auth-algorithm"
        headers[normalized] = str(value).strip()
    return headers


def _ensure_dashboard_user(db: Session) -> User:
    if not settings.DASHBOARD_USERNAME or not settings.DASHBOARD_PASSWORD:
        raise HTTPException(status_code=500, detail="Dashboard auth is misconfigured. Set DASHBOARD_USERNAME and DASHBOARD_PASSWORD in the backend environment.")

    user = db.query(User).filter(User.username == settings.DASHBOARD_USERNAME).first()
    if user is not None:
        return user

    user = User(
        username=settings.DASHBOARD_USERNAME,
        password_hash=hashlib.sha256(settings.DASHBOARD_PASSWORD.encode("utf-8")).hexdigest(),
        is_active=True,
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


def _create_dashboard_session(db: Session, username: str) -> str:
    if not settings.DASHBOARD_USERNAME or not settings.DASHBOARD_PASSWORD:
        raise HTTPException(status_code=500, detail="Dashboard auth is misconfigured.")

    if username != settings.DASHBOARD_USERNAME:
        raise HTTPException(status_code=401, detail="Invalid dashboard credentials.")

    user = _ensure_dashboard_user(db)
    token = secrets.token_urlsafe(32)
    expiry = datetime.now(timezone.utc) + timedelta(minutes=settings.SESSION_TOKEN_TTL_MINUTES)
    db.add(SessionToken(user_id=user.id, token_hash=_hash_session_token(token), expires_at=expiry, revoked=False))
    db.commit()
    return token


def _get_dashboard_session_token(request: Request) -> str | None:
    cookie_name = getattr(settings, "DASHBOARD_SESSION_COOKIE", "dashboard_session")
    cookie_value = request.cookies.get(cookie_name)
    if not cookie_value:
        return None
    return cookie_value.strip() or None


def _require_dashboard_auth(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not settings.DASHBOARD_AUTH_REQUIRED:
        return {"authenticated": True, "user": settings.DASHBOARD_USERNAME or "local-dev"}

    session_token = _get_dashboard_session_token(request)
    if not session_token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    token_hash = _hash_session_token(session_token)
    session = (
        db.query(SessionToken)
        .filter(SessionToken.token_hash == token_hash, SessionToken.revoked.is_(False))
        .first()
    )
    if not session or session.expires_at <= datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Authentication required.")

    user = db.query(User).filter(User.id == session.user_id).first()
    if not user:
        raise HTTPException(status_code=401, detail="Authentication required.")

    return {"authenticated": True, "user": user.username}


def _is_protected_dashboard_route(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in _SENSITIVE_ROUTE_PREFIXES)


@app.middleware("http")
async def dashboard_auth_middleware(request: Request, call_next):
    if not settings.DASHBOARD_AUTH_REQUIRED:
        return await call_next(request)

    if request.method == "OPTIONS":
        return await call_next(request)

    if request.url.path.startswith("/api/paypal/webhooks"):
        return await call_next(request)

    if request.url.path.startswith("/api/dashboard/login") or request.url.path.startswith("/api/dashboard/logout") or request.url.path.startswith("/api/dashboard/session"):
        return await call_next(request)

    if not _is_protected_dashboard_route(request.url.path):
        return await call_next(request)

    db = SessionLocal()
    try:
        session = _get_dashboard_session_token(request)
        if not session:
            return JSONResponse(status_code=401, content={"detail": "Authentication required."})

        token_hash = _hash_session_token(session)
        db_record = (
            db.query(SessionToken)
            .filter(SessionToken.token_hash == token_hash, SessionToken.revoked.is_(False))
            .first()
        )
        if not db_record or db_record.expires_at <= datetime.now(timezone.utc):
            return JSONResponse(status_code=401, content={"detail": "Authentication required."})
    finally:
        db.close()

    return await call_next(request)


def verify_paypal_webhook_signature(payload: dict[str, Any], request: Request) -> tuple[bool, str]:
    webhook_id = (settings.PAYPAL_WEBHOOK_ID or "").strip()
    if not webhook_id:
        return False, "PAYPAL_WEBHOOK_ID is not configured in the backend environment."

    headers = _webhook_headers(request)
    required = {
        "paypal-transmission-id": "PayPal-Transmission-Id",
        "paypal-transmission-time": "PayPal-Transmission-Time",
        "paypal-transmission-sig": "PayPal-Transmission-Sig",
        "paypal-cert-url": "PayPal-Cert-Url",
    }
    missing = [header_name for header_key, header_name in required.items() if not headers.get(header_key)]
    if missing:
        return False, f"Missing required PayPal webhook headers: {', '.join(missing)}"

    auth_algo = headers.get("paypal-auth-algorithm", "SHA256withRSA")
    verification_payload = {
        "auth_algo": auth_algo,
        "cert_url": headers["paypal-cert-url"],
        "transmission_id": headers["paypal-transmission-id"],
        "transmission_sig": headers["paypal-transmission-sig"],
        "transmission_time": headers["paypal-transmission-time"],
        "webhook_id": webhook_id,
        "webhook_event": payload,
    }

    try:
        response = requests.post(
            f"{settings.PAYPAL_API_BASE}/v1/notifications/verify-webhook-signature",
            auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET),
            json=verification_payload,
            timeout=30,
        )
    except requests.RequestException as exc:
        return False, f"PayPal webhook verification request failed: {exc}"

    if response.status_code != 200:
        return False, f"PayPal webhook verification returned HTTP {response.status_code}."

    result = response.json() if hasattr(response, "json") else {}
    status = str(result.get("verification_status", "")).upper()
    if status != "SUCCESS":
        return False, f"PayPal webhook verification failed: {result}"
    return True, "verified"


def _ensure_utc_datetime(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_paypal_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return _ensure_utc_datetime(value)
    if isinstance(value, str):
        cleaned = value.strip()
        if not cleaned:
            return None
        try:
            return datetime.fromisoformat(cleaned.replace("Z", "+00:00")).astimezone(timezone.utc)
        except ValueError:
            return None
    return None


def _normalize_webhook_transaction(payload: dict[str, Any]) -> dict[str, Any] | None:
    resource = payload.get("resource") or {}
    if not isinstance(resource, dict):
        return None

    resource_id = resource.get("id")
    if not resource_id:
        return None

    amount = resource.get("amount") or {}
    if isinstance(amount, dict):
        amount_value = amount.get("value") or "0"
        currency = amount.get("currency_code") or amount.get("currency") or "USD"
    else:
        amount_value = "0"
        currency = "USD"

    status_value = resource.get("status") or payload.get("status") or "unknown"
    event_type = payload.get("event_type", "unknown")
    return {
        "paypal_transaction_id": str(resource_id),
        "parent_transaction_id": resource.get("parent_payment"),
        "order_id": resource.get("invoice_id") or resource.get("order_id") or resource.get("billing_agreement_id"),
        "resource_type": payload.get("resource_type"),
        "transaction_type": event_type,
        "amount": str(amount_value),
        "currency": str(currency),
        "transaction_status": str(status_value).lower(),
        "payment_status": str(status_value).lower(),
        "environment": settings.PAYPAL_MODE,
        "source_reference": f"webhook:{event_type}",
        "created_at": _parse_paypal_datetime(payload.get("create_time")),
        "payload": payload,
    }


def _extract_capture_details(payload: dict[str, Any]) -> dict[str, Any]:
    status = str((payload or {}).get("status") or "").upper()
    capture_id = None
    amount = None
    currency = None
    transaction_id = None

    purchase_units = (payload or {}).get("purchase_units") or []
    for unit in purchase_units:
        payments = (unit or {}).get("payments") or {}
        captures = payments.get("captures") or []
        for capture in captures:
            if not capture_id and capture.get("id"):
                capture_id = str(capture["id"])
            if not transaction_id and capture.get("id"):
                transaction_id = str(capture["id"])
            if not amount and isinstance(capture.get("amount"), dict):
                amount = str(capture["amount"].get("value") or "0")
                currency = str(capture["amount"].get("currency_code") or capture["amount"].get("currency") or "USD")
            if not status and capture.get("status"):
                status = str(capture.get("status")).upper()

    if not capture_id:
        capture_id = str((payload or {}).get("id") or "") or None
    if not transaction_id:
        transaction_id = capture_id
    if not amount:
        amount_value = ((payload or {}).get("amount") or {})
        if isinstance(amount_value, dict):
            amount = str(amount_value.get("value") or "0")
            currency = str(amount_value.get("currency_code") or amount_value.get("currency") or "USD")
    if not currency:
        currency = "USD"
    if not amount:
        amount = "0"

    return {
        "order_id": (payload or {}).get("id") or None,
        "capture_id": capture_id,
        "transaction_id": transaction_id,
        "amount": amount,
        "currency": currency,
        "status": status,
    }


def _store_completed_capture_transaction(db: Session, order_id: str, capture_details: dict[str, Any]) -> PayPalTransactionRecord | None:
    final_status = str(capture_details.get("status") or "").upper()
    if final_status != "COMPLETED":
        return None

    transaction_id = capture_details.get("transaction_id") or capture_details.get("capture_id") or order_id
    if not transaction_id:
        return None

    existing = db.query(PayPalTransactionRecord).filter(PayPalTransactionRecord.paypal_transaction_id == transaction_id).first()
    if existing is not None:
        return existing

    record = PayPalTransactionRecord(
        paypal_transaction_id=str(transaction_id),
        order_id=str(order_id),
        resource_type="capture",
        transaction_type="CAPTURE",
        amount=str(capture_details.get("amount") or "0"),
        currency=str(capture_details.get("currency") or "USD"),
        transaction_status="COMPLETED",
        payment_status="COMPLETED",
        environment=settings.PAYPAL_MODE,
        source_reference=f"/v2/checkout/orders/{order_id}/capture",
        created_at=datetime.now(timezone.utc),
        captured_at=datetime.now(timezone.utc),
        payload=capture_details,
    )
    db.add(record)
    db.commit()
    return record


def _store_payout_transaction(db: Session, payout_payload: dict[str, Any]) -> PayPalTransactionRecord | None:
    batch_header = payout_payload.get("batch_header") or {}
    items = payout_payload.get("items") or []
    item = items[0] if items else {}
    batch_status = str(batch_header.get("batch_status") or item.get("transaction_status") or "PENDING").upper()
    payout_id = batch_header.get("payout_batch_id") or item.get("payout_item_id") or "UNKNOWN"
    transaction_id = item.get("payout_item_id") or payout_id
    if not transaction_id:
        return None

    existing = db.query(PayPalTransactionRecord).filter(PayPalTransactionRecord.paypal_transaction_id == transaction_id).first()
    if existing is not None:
        return existing

    amount_payload = item.get("amount") or batch_header.get("amount") or {}
    if not isinstance(amount_payload, dict):
        amount_payload = {}
    amount_value = str(amount_payload.get("value") or "0")
    amount_currency = str(amount_payload.get("currency") or "USD").upper()
    receiver_email = str(item.get("receiver") or "unknown@example.com")
    record = PayPalTransactionRecord(
        paypal_transaction_id=str(transaction_id),
        parent_transaction_id=str(batch_header.get("payout_batch_id") or payout_id),
        order_id=str(batch_header.get("payout_batch_id") or payout_id),
        resource_type="payout",
        transaction_type="PAYOUT",
        payer_name="PayPal Business Account",
        payer_email=receiver_email,
        amount=amount_value,
        currency=amount_currency,
        transaction_status=batch_status.lower(),
        payment_status=batch_status.lower(),
        payment_mode="payout",
        environment=settings.PAYPAL_MODE,
        source_reference="/v1/payments/payouts",
        created_at=datetime.now(timezone.utc),
        captured_at=datetime.now(timezone.utc),
        payload=payout_payload,
    )
    db.add(record)
    db.commit()
    return record


def _store_webhook_event(db: Session, payload: dict[str, Any], verified: bool) -> tuple[dict[str, Any], bool]:
    event_id = payload.get("id") or payload.get("event_id")
    if not event_id:
        raise HTTPException(status_code=400, detail="PayPal webhook payload is missing a unique event identifier.")

    existing = db.query(PayPalWebhookEvent).filter(PayPalWebhookEvent.event_id == event_id).first()
    if existing:
        return {
            "status": "received",
            "duplicate": True,
            "event_id": event_id,
            "event_type": existing.event_type,
            "message": "Duplicate PayPal webhook event was ignored.",
        }, True

    resource = payload.get("resource") or {}
    resource_id = resource.get("id") if isinstance(resource, dict) else None
    amount = resource.get("amount") if isinstance(resource, dict) else None
    event_type = payload.get("event_type", "UNKNOWN")
    summary = payload.get("summary")

    event_record = PayPalWebhookEvent(
        event_id=str(event_id),
        event_type=str(event_type),
        resource_id=str(resource_id) if resource_id else None,
        amount=str((amount or {}).get("value")) if isinstance(amount, dict) and amount.get("value") else None,
        currency=(amount or {}).get("currency_code") if isinstance(amount, dict) and amount.get("currency_code") else None,
        status="verified" if verified else "rejected",
        summary=summary,
        verified=verified,
        verified_at=datetime.now(timezone.utc) if verified else None,
        raw_payload=payload,
    )
    db.add(event_record)

    if verified and event_type in _SUPPORTED_WEBHOOK_EVENTS:
        normalized = _normalize_webhook_transaction(payload)
        if normalized:
            existing_tx = db.query(PayPalTransactionRecord).filter(PayPalTransactionRecord.paypal_transaction_id == normalized["paypal_transaction_id"]).first()
            if existing_tx is None:
                db.add(
                    PayPalTransactionRecord(
                        paypal_transaction_id=normalized["paypal_transaction_id"],
                        parent_transaction_id=normalized.get("parent_transaction_id"),
                        order_id=normalized.get("order_id"),
                        resource_type=normalized.get("resource_type"),
                        transaction_type=normalized.get("transaction_type"),
                        amount=str(normalized.get("amount") or "0"),
                        currency=normalized.get("currency"),
                        transaction_status=normalized.get("transaction_status"),
                        payment_status=normalized.get("payment_status"),
                        environment=normalized.get("environment"),
                        source_reference=normalized.get("source_reference"),
                        created_at=_parse_paypal_datetime(payload.get("create_time")),
                        payload=normalized.get("payload"),
                    )
                )

            alerts = generate_fraud_alerts([normalized])
            for alert in alerts:
                tx_id = alert.get("paypal_transaction_id") or normalized["paypal_transaction_id"]
                duplicate_alert = (
                    db.query(FraudAlert)
                    .filter(FraudAlert.paypal_transaction_id == tx_id, FraudAlert.alert_type == alert.get("alert_type"))
                    .first()
                )
                if duplicate_alert is None:
                    db.add(
                        FraudAlert(
                            paypal_transaction_id=tx_id,
                            alert_type=alert.get("alert_type"),
                            severity=alert.get("severity"),
                            risk_score=alert.get("risk_score", 0),
                            message=alert.get("message"),
                            evidence=alert.get("evidence"),
                            source_reference=normalized.get("source_reference"),
                            status=alert.get("status", "review"),
                        )
                    )

    db.commit()
    return {
        "status": "received",
        "duplicate": False,
        "event_id": event_id,
        "event_type": event_type,
        "message": "Verified PayPal webhook event stored and processed.",
    }, False


@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": settings.PAYPAL_MODE,
        "sandbox_mode": settings.PAYPAL_MODE == "sandbox",
    }


@app.get("/api/dashboard/session")
def dashboard_session(request: Request, db: Session = Depends(get_db)):
    if not settings.DASHBOARD_AUTH_REQUIRED:
        return {"authenticated": True, "user": settings.DASHBOARD_USERNAME or "local-dev"}

    token = _get_dashboard_session_token(request)
    if not token:
        return {"authenticated": False, "user": None}

    token_hash = _hash_session_token(token)
    session = (
        db.query(SessionToken)
        .filter(SessionToken.token_hash == token_hash, SessionToken.revoked.is_(False))
        .first()
    )
    if not session or session.expires_at <= datetime.now(timezone.utc):
        return {"authenticated": False, "user": None}

    user = db.query(User).filter(User.id == session.user_id).first()
    return {"authenticated": bool(user), "user": user.username if user else None}


@app.post("/api/dashboard/login")
def dashboard_login(payload: DashboardAuthRequest, request: Request, db: Session = Depends(get_db)):
    if not settings.DASHBOARD_USERNAME or not settings.DASHBOARD_PASSWORD:
        raise HTTPException(status_code=500, detail="Dashboard auth is not configured.")

    if payload.username != settings.DASHBOARD_USERNAME or payload.password != settings.DASHBOARD_PASSWORD:
        raise HTTPException(status_code=401, detail="Invalid dashboard credentials.")

    token = _create_dashboard_session(db, payload.username)
    response = JSONResponse({"status": "ok", "message": "Dashboard authenticated."})
    response.set_cookie(
        key=settings.DASHBOARD_SESSION_COOKIE,
        value=token,
        httponly=True,
        samesite="lax",
        secure=settings.APP_ENV.lower() == "production",
        path="/",
        max_age=settings.SESSION_TOKEN_TTL_MINUTES * 60,
    )
    return response


@app.post("/api/dashboard/logout")
def dashboard_logout(request: Request, db: Session = Depends(get_db)):
    token = _get_dashboard_session_token(request)
    if token:
        token_hash = _hash_session_token(token)
        session = db.query(SessionToken).filter(SessionToken.token_hash == token_hash).first()
        if session:
            session.revoked = True
            db.commit()

    response = JSONResponse({"status": "ok", "message": "Signed out."})
    response.delete_cookie(
        key=settings.DASHBOARD_SESSION_COOKIE,
        path="/",
        httponly=True,
        samesite="lax",
        secure=settings.APP_ENV.lower() == "production",
    )
    return response


@app.get("/api/paypal/config-status")
def config_status():
    configured = bool(settings.PAYPAL_CLIENT_ID and settings.PAYPAL_CLIENT_SECRET)
    is_live = settings.PAYPAL_MODE == "live"
    live_payouts_enabled = bool(getattr(settings, "PAYPAL_LIVE_PAYOUTS_ENABLED", False))
    return {
        "mode": settings.PAYPAL_MODE,
        "configured": configured,
        "live_mode": is_live,
        "live_payouts_enabled": live_payouts_enabled,
        "api_base": settings.PAYPAL_API_BASE,
        "missing": [
            key for key, value in {"PAYPAL_CLIENT_ID": settings.PAYPAL_CLIENT_ID, "PAYPAL_CLIENT_SECRET": settings.PAYPAL_CLIENT_SECRET}.items() if not value
        ],
        "status": "ready" if configured else "blocked",
        "message": (
            "PayPal live configuration is present, but live payouts remain disabled until the account is approved for real-money transfers."
            if is_live and configured
            else "PayPal OAuth is unavailable until the backend receives valid credentials."
            if not configured
            else "PayPal Sandbox configuration is present."
        ),
    }


@app.post("/api/paypal/import")
def import_transactions(
    start_date: str = Query(...),
    end_date: str = Query(...),
    db: Session = Depends(get_db),
):
    try:
        records = fetch_transaction_history(start_date, end_date)
    except PayPalPermissionError as exc:
        return {
            "status": "blocked",
            "permission_error": True,
            "message": str(exc),
            "imported_count": 0,
            "duplicates_skipped": 0,
        }
    except PayPalConfigError as exc:
        return {
            "status": "blocked",
            "permission_error": False,
            "message": str(exc),
            "imported_count": 0,
            "duplicates_skipped": 0,
        }
    except RuntimeError as exc:
        return {
            "status": "blocked",
            "permission_error": False,
            "message": f"PayPal API call failed: {exc}",
            "imported_count": 0,
            "duplicates_skipped": 0,
        }

    imported_count = 0
    duplicates_skipped = 0
    for record in records:
        paypal_transaction_id = record.get("paypal_transaction_id")
        if not paypal_transaction_id:
            continue

        if db.query(PayPalTransactionRecord).filter(PayPalTransactionRecord.paypal_transaction_id == paypal_transaction_id).first():
            duplicates_skipped += 1
            continue

        db.add(
            PayPalTransactionRecord(
                paypal_transaction_id=paypal_transaction_id,
                parent_transaction_id=record.get("parent_transaction_id"),
                order_id=record.get("order_id"),
                resource_type=record.get("resource_type"),
                transaction_type=record.get("transaction_type"),
                payer_name=record.get("payer_name"),
                payer_email=record.get("payer_email"),
                amount=str(record.get("amount") or "0"),
                currency=record.get("currency"),
                transaction_status=record.get("transaction_status"),
                payment_status=record.get("payment_status"),
                payment_mode=record.get("payment_mode"),
                environment=record.get("environment", settings.PAYPAL_MODE),
                source_reference=record.get("source_reference", "/v1/reporting/transactions"),
                invoice_id=record.get("invoice_id"),
                created_at=record.get("created_at"),
                captured_at=record.get("captured_at"),
                payload=record.get("payload"),
                permissions_error=record.get("permissions_error"),
            )
        )
        imported_count += 1

    db.commit()

    db_rows = db.query(PayPalTransactionRecord).all()
    normalized_rows = [
        {
            "paypal_transaction_id": row.paypal_transaction_id,
            "payer_email": row.payer_email,
            "payer_name": row.payer_name,
            "amount": row.amount,
            "currency": row.currency,
            "transaction_status": row.transaction_status,
            "created_at": row.created_at.isoformat() if row.created_at else None,
            "captured_at": row.captured_at.isoformat() if row.captured_at else None,
        }
        for row in db_rows
    ]
    alerts = generate_fraud_alerts(normalized_rows)

    for alert in alerts:
        tx_id = alert.get("paypal_transaction_id")
        if not tx_id:
            continue
        if not db.query(FraudAlert).filter(FraudAlert.paypal_transaction_id == tx_id, FraudAlert.alert_type == alert.get("alert_type")).first():
            db.add(
                FraudAlert(
                    paypal_transaction_id=tx_id,
                    alert_type=alert.get("alert_type"),
                    severity=alert.get("severity"),
                    risk_score=alert.get("risk_score", 0),
                    message=alert.get("message"),
                    evidence=alert.get("evidence"),
                    source_reference="/v1/reporting/transactions",
                    status=alert.get("status", "review"),
                )
            )
    db.commit()

    return {
        "status": "ok",
        "environment": settings.PAYPAL_MODE,
        "imported_count": imported_count,
        "duplicates_skipped": duplicates_skipped,
        "message": "Retrieved transactions were stored with unique PayPal transaction IDs.",
        "alerts": alerts,
    }


def serialize_transaction_row(row):
    return {
        "id": row.id,
        "paypal_transaction_id": row.paypal_transaction_id,
        "parent_transaction_id": row.parent_transaction_id,
        "order_id": row.order_id,
        "resource_type": row.resource_type,
        "transaction_type": row.transaction_type,
        "payer_name": row.payer_name,
        "payer_email": row.payer_email,
        "amount": row.amount,
        "currency": row.currency,
        "transaction_status": row.transaction_status,
        "payment_status": row.payment_status,
        "environment": row.environment,
        "source_reference": row.source_reference,
        "invoice_id": row.invoice_id,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "captured_at": row.captured_at.isoformat() if row.captured_at else None,
        "permissions_error": row.permissions_error,
    }


@app.get("/api/paypal/transactions")
def list_transactions(db: Session = Depends(get_db)):
    rows = db.query(PayPalTransactionRecord).order_by(PayPalTransactionRecord.imported_at.desc()).all()
    return {
        "count": len(rows),
        "environment": settings.PAYPAL_MODE,
        "results": [serialize_transaction_row(row) for row in rows],
    }


@app.get("/api/paypal/transactions/search")
def search_transaction_by_id(
    transaction_id: str | None = Query(default=None),
    order_id: str | None = Query(default=None),
    amount: str | None = Query(default=None),
    payment_status: str | None = Query(default=None),
    db: Session = Depends(get_db),
):
    filters = []
    if transaction_id:
        filters.append(PayPalTransactionRecord.paypal_transaction_id == transaction_id)
    if order_id:
        filters.append(
            or_(
                PayPalTransactionRecord.order_id == order_id,
                PayPalTransactionRecord.parent_transaction_id == order_id,
                PayPalTransactionRecord.invoice_id == order_id,
            )
        )
    if amount:
        filters.append(PayPalTransactionRecord.amount == str(amount).strip())
    if payment_status:
        filters.append(PayPalTransactionRecord.payment_status == payment_status.strip().upper())

    query = db.query(PayPalTransactionRecord)
    if filters:
        query = query.filter(*filters)

    row = query.order_by(PayPalTransactionRecord.imported_at.desc()).first()
    if row is None:
        return {"status": "not_found", "found": False, "message": "No PayPal Sandbox transaction matched the supplied filters.", "transaction": None}
    return {"status": "ok", "found": True, "message": "PayPal Sandbox transaction found.", "transaction": serialize_transaction_row(row)}


@app.get("/api/paypal/transactions/{transaction_id}")
def get_transaction_detail(transaction_id: str, db: Session = Depends(get_db)):
    row = db.query(PayPalTransactionRecord).filter(PayPalTransactionRecord.paypal_transaction_id == transaction_id).first()
    if row is None:
        return {"status": "not_found", "found": False, "message": "No PayPal Sandbox transaction was found for the supplied transaction ID.", "transaction": None}
    return {"status": "ok", "found": True, "message": "PayPal Sandbox transaction found.", "transaction": serialize_transaction_row(row)}


@app.get("/api/paypal/alerts")
def list_alerts(db: Session = Depends(get_db)):
    rows = db.query(FraudAlert).order_by(FraudAlert.created_at.desc()).all()
    return {
        "count": len(rows),
        "results": [
            {
                "alert_id": row.id,
                "paypal_transaction_id": row.paypal_transaction_id,
                "alert_type": row.alert_type,
                "severity": row.severity,
                "risk_score": row.risk_score,
                "message": row.message,
                "evidence": row.evidence,
                "status": row.status,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
    }


@app.get("/api/paypal/fraud/analytics")
def fraud_analytics(db: Session = Depends(get_db)):
    rows = db.query(PayPalTransactionRecord).order_by(PayPalTransactionRecord.imported_at.desc()).all()
    records = [serialize_transaction_row(row) for row in rows]
    payer_counts = defaultdict(int)
    for record in records:
        payer = record.get("payer_email") or record.get("payer_name") or "unknown"
        payer_counts[payer] += 1

    scored_transactions = []
    for record in records:
        payer = record.get("payer_email") or record.get("payer_name") or "unknown"
        amount = float(record.get("amount") or 0.0)
        created = _parse_paypal_datetime(record.get("created_at"))
        feature_record = {
            "paypal_transaction_id": record.get("paypal_transaction_id"),
            "amount": amount,
            "transaction_frequency": payer_counts.get(payer, 0),
            "unusual_transaction_time": 1 if created and (created.hour < 6 or created.hour > 22) else 0,
            "repeated_recipient": 1 if payer_counts.get(payer, 0) > 1 else 0,
            "transaction_velocity": min(1.0, payer_counts.get(payer, 0) / 10.0),
            "unusual_spending_pattern": 1 if amount > 1000 else 0,
        }
        score = score_transaction(feature_record)
        scored_transactions.append(
            {
                "transaction_id": score["transaction_id"],
                "amount": record.get("amount"),
                "payer_email": record.get("payer_email"),
                "currency": record.get("currency"),
                "fraud_probability": score["fraud_probability"],
                "risk_level": score["risk_level"],
                "model_type": score["model_type"],
                "training_data_source": score["training_data_source"],
            }
        )

    summary = summarize_ml_scores(
        [
            {
                "paypal_transaction_id": item["transaction_id"],
                "amount": item["amount"],
                "transaction_frequency": 1,
                "unusual_transaction_time": 1 if item["risk_level"] == "HIGH RISK" else 0,
                "repeated_recipient": 1 if item["risk_level"] in {"MEDIUM RISK", "HIGH RISK"} else 0,
                "transaction_velocity": min(1.0, item["fraud_probability"] / 100.0),
                "unusual_spending_pattern": 1 if item["fraud_probability"] > 70 else 0,
            }
            for item in scored_transactions
        ]
    )
    model = create_ml_fraud_model()

    return {
        "status": "ok",
        "environment": settings.PAYPAL_MODE,
        "training_data_source": "synthetic",
        "model_type": "random_forest",
        "model_metrics": model["metrics"],
        "risk_thresholds": model["risk_thresholds"],
        "summary": {
            "average_risk_score": summary["average_risk_score"],
            "risk_distribution": summary["risk_distribution"],
            "scored_transaction_count": len(scored_transactions),
        },
        "scored_transactions": scored_transactions[:25],
        "message": "This dashboard uses a synthetic Random Forest training set. Real PayPal Sandbox transactions are scored for review and monitoring, but they are never used for model training.",
    }


@app.get("/api/paypal/webhook-events")
def list_webhook_events(db: Session = Depends(get_db)):
    rows = db.query(PayPalWebhookEvent).order_by(PayPalWebhookEvent.created_at.desc()).all()
    return {
        "count": len(rows),
        "results": [
            {
                "event_id": row.event_id,
                "event_type": row.event_type,
                "resource_id": row.resource_id,
                "amount": row.amount,
                "currency": row.currency,
                "status": row.status,
                "summary": row.summary,
                "verified": row.verified,
                "source": row.source,
                "verified_at": row.verified_at.isoformat() if row.verified_at else None,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in rows
        ],
    }


@app.post("/api/paypal/webhooks")
async def handle_paypal_webhook(request: Request, db: Session = Depends(get_db)):
    try:
        payload = json.loads((await request.body()).decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        raise HTTPException(status_code=400, detail="PayPal webhook payload must be valid JSON.")

    valid, reason = verify_paypal_webhook_signature(payload, request)
    if not valid:
        return JSONResponse(
            status_code=401,
            content={
                "status": "rejected",
                "duplicate": False,
                "message": "Invalid PayPal webhook signature.",
                "error": reason,
            },
        )

    result, duplicate = _store_webhook_event(db, payload, verified=True)
    if duplicate:
        result["duplicate"] = True
        return JSONResponse(status_code=200, content=result)

    return JSONResponse(status_code=200, content={**result, "duplicate": False})


@app.post("/api/paypal/alerts/{alert_id}/ai-explanation")
def get_ai_explanation_for_alert(alert_id: int, db: Session = Depends(get_db)):
    alert_row = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if alert_row is None:
        raise HTTPException(status_code=404, detail="Fraud alert not found.")

    transaction_row = (
        db.query(PayPalTransactionRecord)
        .filter(PayPalTransactionRecord.paypal_transaction_id == alert_row.paypal_transaction_id)
        .first()
    )

    transaction_payload = {
        "paypal_transaction_id": transaction_row.paypal_transaction_id if transaction_row else alert_row.paypal_transaction_id,
        "amount": transaction_row.amount if transaction_row else None,
        "currency": transaction_row.currency if transaction_row else None,
        "transaction_status": transaction_row.transaction_status if transaction_row else None,
        "payment_status": transaction_row.payment_status if transaction_row else None,
        "environment": transaction_row.environment if transaction_row else settings.PAYPAL_MODE,
        "source_reference": transaction_row.source_reference if transaction_row else "/v1/reporting/transactions",
        "created_at": transaction_row.created_at.isoformat() if transaction_row and transaction_row.created_at else None,
    }

    alert_payload = {
        "alert_type": alert_row.alert_type,
        "severity": alert_row.severity,
        "risk_score": alert_row.risk_score,
        "message": alert_row.message,
        "evidence": alert_row.evidence,
        "status": alert_row.status,
    }

    result = generate_ai_explanation(alert_payload, transaction_payload)
    result["alert_id"] = alert_id
    return result


@app.patch("/api/paypal/alerts/{alert_id}")
def update_alert_status(alert_id: int, status: str = Query(...), db: Session = Depends(get_db)):
    row = db.query(FraudAlert).filter(FraudAlert.id == alert_id).first()
    if row is None:
        raise HTTPException(status_code=404, detail="Fraud alert not found.")

    row.status = status.strip().lower()
    db.commit()
    db.refresh(row)
    return {
        "status": row.status,
        "alert_id": row.id,
        "message": "Fraud alert status updated.",
        "alert": {
            "alert_id": row.id,
            "paypal_transaction_id": row.paypal_transaction_id,
            "alert_type": row.alert_type,
            "severity": row.severity,
            "risk_score": row.risk_score,
            "status": row.status,
        },
    }


@app.get("/api/paypal/balance")
def get_balance():
    try:
        payload = fetch_account_balance()
        normalized = normalize_account_balance(payload)
        return {
            "status": "ok",
            "environment": settings.PAYPAL_MODE,
            "message": "Balance reporting data is available.",
            "payload": normalized,
            "balance": normalized,
        }
    except PayPalPermissionError as exc:
        return {
            "status": "blocked",
            "permission_error": True,
            "message": str(exc),
            "payload": None,
            "balance": None,
        }
    except PayPalConfigError as exc:
        return {
            "status": "blocked",
            "permission_error": False,
            "message": str(exc),
            "payload": None,
            "balance": None,
        }


@app.get("/api/paypal/orders/{order_id}")
def get_order(order_id: str):
    try:
        return {
            "status": "ok",
            "result": fetch_order_details(order_id),
        }
    except PayPalPermissionError as exc:
        return {
            "status": "blocked",
            "permission_error": True,
            "message": str(exc),
        }
    except PayPalConfigError as exc:
        return {
            "status": "blocked",
            "permission_error": False,
            "message": str(exc),
        }


@app.post("/api/paypal/payout")
@app.post("/api/paypal/payouts")
def create_payout_route(
    payload: PayoutRequest,
    db: Session = Depends(get_db),
):
    try:
        payout_result = create_payout(
            recipient_email=payload.recipient_email,
            amount=payload.amount,
            currency=payload.currency.upper(),
            note=payload.note,
        )
        payout_status = str((payout_result.get("batch_header") or {}).get("batch_status") or "PENDING").upper()
        item_status = str(((payout_result.get("items") or [{}])[0]).get("transaction_status") or payout_status).upper()
        payout_status = item_status or payout_status

        stored = _store_payout_transaction(db, payout_result)
        if stored is not None:
            normalized = {
                "paypal_transaction_id": stored.paypal_transaction_id,
                "payer_email": stored.payer_email,
                "payer_name": stored.payer_name,
                "amount": stored.amount,
                "currency": stored.currency,
                "transaction_status": stored.transaction_status,
                "payment_status": stored.payment_status,
                "created_at": stored.created_at,
                "captured_at": stored.captured_at,
                "source_reference": stored.source_reference,
            }
            alerts = generate_fraud_alerts([normalized])
            for alert in alerts:
                duplicate_alert = (
                    db.query(FraudAlert)
                    .filter(FraudAlert.paypal_transaction_id == alert.get("paypal_transaction_id"), FraudAlert.alert_type == alert.get("alert_type"))
                    .first()
                )
                if duplicate_alert is None:
                    db.add(
                        FraudAlert(
                            paypal_transaction_id=alert.get("paypal_transaction_id"),
                            alert_type=alert.get("alert_type"),
                            severity=alert.get("severity"),
                            risk_score=alert.get("risk_score", 0),
                            message=alert.get("message"),
                            evidence=alert.get("evidence"),
                            source_reference="/v1/payments/payouts",
                            status=alert.get("status", "review"),
                        )
                    )
            db.commit()

        try:
            balance = fetch_account_balance()
            balance_message = "PayPal balance refreshed after the payout request." if payout_status == "SUCCESS" else "PayPal balance refreshed after the payout request was submitted."
        except PayPalPermissionError as exc:
            balance = {"status": "blocked", "permission_error": True, "message": str(exc)}
            balance_message = "The payout request was accepted by PayPal, but the balance refresh is currently blocked by permissions."
        except (PayPalConfigError, RuntimeError) as exc:
            balance = {"status": "blocked", "permission_error": False, "message": str(exc)}
            balance_message = "The payout request was accepted by PayPal, but the balance refresh is currently unavailable."

        if payout_status == "SUCCESS":
            message = "PayPal payout was confirmed as successful. The dashboard balance and transaction list have been refreshed."
        elif payout_status == "FAILED":
            message = "PayPal payout failed. The payout status was returned as FAILED and no success was claimed."
        else:
            message = "PayPal payout was submitted and is pending confirmation. The dashboard may show a final status after the payout is processed."

        return {
            "status": payout_status.lower(),
            "payout_status": payout_status,
            "batch_id": (payout_result.get("batch_header") or {}).get("payout_batch_id"),
            "item_id": ((payout_result.get("items") or [{}])[0]).get("payout_item_id"),
            "recipient": ((payout_result.get("items") or [{}])[0]).get("receiver"),
            "amount": ((payout_result.get("items") or [{}])[0]).get("amount", {}).get("value"),
            "currency": ((payout_result.get("items") or [{}])[0]).get("amount", {}).get("currency"),
            "message": message,
            "balance": balance,
            "balance_message": balance_message,
            "result": payout_result,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except HTTPException:
        raise
    except PayPalConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except PayPalPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/api/paypal/payouts/{batch_id}")
def get_payout_status_route(batch_id: str):
    try:
        payout_details = fetch_payout_batch_details(batch_id)
        batch_header = payout_details.get("batch_header") or {}
        items = payout_details.get("items") or []
        item = items[0] if items else {}
        payout_status = str(batch_header.get("batch_status") or item.get("transaction_status") or "PENDING").upper()
        return {
            "status": payout_status.lower(),
            "payout_status": payout_status,
            "batch_id": batch_header.get("payout_batch_id") or batch_id,
            "item_id": item.get("payout_item_id"),
            "recipient": item.get("receiver"),
            "amount": (item.get("amount") or {}).get("value"),
            "currency": (item.get("amount") or {}).get("currency"),
            "message": "PayPal payout batch status was confirmed from the official API.",
            "result": payout_details,
        }
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except PayPalConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))
    except PayPalPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.get("/api/paypal/captures/{capture_id}")
def get_capture(capture_id: str):
    try:
        return {
            "status": "ok",
            "result": fetch_capture_details(capture_id),
        }
    except PayPalPermissionError as exc:
        return {
            "status": "blocked",
            "permission_error": True,
            "message": str(exc),
        }
    except PayPalConfigError as exc:
        return {
            "status": "blocked",
            "permission_error": False,
            "message": str(exc),
        }
@app.post("/api/paypal/orders")
def create_order(
    payload: CreateOrderRequest,
    db: Session = Depends(get_db),
):
    try:
        result = create_checkout_order(
            amount=payload.amount,
            currency=payload.currency.upper(),
        )

        approval_url = next(
            (
                link["href"]
                for link in result.get("links", [])
                if link.get("rel") == "approve"
            ),
            None,
        )

        if not approval_url:
            raise HTTPException(
                status_code=502,
                detail="PayPal approval URL was not returned. The buyer could not be redirected to approve the $1 order.",
            )

        return {
            "status": "ok",
            "order_id": result.get("id"),
            "paypal_status": result.get("status"),
            "approval_url": approval_url,
            "message": "PayPal order created successfully. Complete buyer approval in the PayPal checkout window.",
        }

    except HTTPException:
        raise

    except PayPalConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    except PayPalPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))


@app.post("/api/paypal/orders/{order_id}/capture")
def capture_order(
    order_id: str,
    db: Session = Depends(get_db),
):
    try:
        result = capture_checkout_order(order_id)
        capture_details = _extract_capture_details(result)
        paypal_status = str(capture_details.get("status") or "").upper()

        if paypal_status != "COMPLETED":
            raise HTTPException(
                status_code=400,
                detail=f"PayPal did not confirm a completed capture for order {order_id}. Final status: {paypal_status or 'UNKNOWN'}.",
            )

        stored = _store_completed_capture_transaction(db, order_id, capture_details)
        if stored is None:
            raise HTTPException(
                status_code=400,
                detail=f"PayPal capture completed for order {order_id}, but the transaction could not be saved to the database.",
            )

        try:
            balance = fetch_account_balance()
            message = "PayPal capture completed successfully, the transaction was stored, and the sandbox balance was refreshed."
        except PayPalPermissionError as exc:
            balance = {"status": "blocked", "permission_error": True, "message": str(exc)}
            message = "PayPal capture completed successfully and the transaction was stored, but the sandbox balance is temporarily unavailable from the Reporting API."
        except (PayPalConfigError, RuntimeError) as exc:
            balance = {"status": "blocked", "permission_error": False, "message": str(exc)}
            message = "PayPal capture completed successfully and the transaction was stored, but the sandbox balance could not be refreshed right now."

        return {
            "status": "ok",
            "order_id": order_id,
            "capture_id": capture_details.get("capture_id"),
            "transaction_id": capture_details.get("transaction_id") or capture_details.get("capture_id"),
            "amount": capture_details.get("amount"),
            "currency": capture_details.get("currency"),
            "paypal_status": paypal_status,
            "result": result,
            "balance": balance,
            "message": message,
        }

    except HTTPException:
        raise

    except PayPalConfigError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    except PayPalPermissionError as exc:
        raise HTTPException(status_code=403, detail=str(exc))

    except requests.RequestException as exc:
        raise HTTPException(status_code=502, detail=str(exc))

    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc))