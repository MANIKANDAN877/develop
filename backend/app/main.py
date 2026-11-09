from __future__ import annotations

import hashlib
import json
import secrets
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

import bcrypt
import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .config import settings
from .db import Base, SessionLocal, ensure_database_schema, engine, get_db
from .fraud import generate_fraud_alerts
from .models import FraudAlert, PayPalTransactionRecord, PayPalWebhookEvent, SessionToken, User
from .paypal import (
    PayPalConfigError,
    PayPalPermissionError,
    fetch_account_balance,
    fetch_capture_details,
    fetch_order_details,
    fetch_transaction_history,
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


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=80)
    password: str = Field(..., min_length=8, max_length=128)


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def _user_payload(user: User) -> dict[str, Any]:
    return {"id": user.id, "username": user.username}


def _build_session_cookie(token: str) -> tuple[str, dict[str, Any]]:
    frontend_host = urlparse(settings.FRONTEND_URL).netloc.lower()
    backend_host = urlparse(settings.BACKEND_URL).netloc.lower()
    same_site = "lax"
    if settings.APP_ENV == "production" and frontend_host and backend_host and frontend_host != backend_host:
        same_site = "none"

    return token, {
        "httponly": True,
        "secure": settings.APP_ENV == "production",
        "samesite": same_site,
        "max_age": settings.SESSION_TOKEN_TTL_MINUTES * 60,
    }


def _ensure_default_user() -> None:
    with SessionLocal() as db:
        if db.query(User).count() > 0:
            return
        username = settings.DASHBOARD_USERNAME.strip() or "admin"
        password = settings.DASHBOARD_PASSWORD.strip() or "admin123"
        db.add(User(username=username, password_hash=hash_password(password)))
        db.commit()


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    if request.url.path.startswith("/api/") and not request.url.path.startswith("/api/auth/login"):
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
        _ensure_default_user()
    except Exception as exc:  # pragma: no cover - depends on local database availability
        print(f"Database unavailable during startup; API remains available in degraded mode: {exc}")


def _webhook_headers(request: Request) -> dict[str, str]:
    return {key.lower(): value for key, value in request.headers.items()}


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


def _parse_paypal_datetime(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
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


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    if settings.ALLOW_LOCAL_DEV_UNAUTH and settings.APP_ENV != "production":
        user = db.query(User).first()
        if user is not None:
            return user
        fallback_username = settings.DASHBOARD_USERNAME.strip() or "admin"
        fallback_user = db.query(User).filter(User.username == fallback_username).first()
        if fallback_user is None:
            fallback_user = User(
                username=fallback_username,
                password_hash=hash_password(settings.DASHBOARD_PASSWORD.strip() or "admin123"),
                is_active=True,
            )
            db.add(fallback_user)
            db.commit()
            db.refresh(fallback_user)
        return fallback_user

    token = request.cookies.get("session_token")
    if not token:
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            token = auth_header.split(" ", 1)[1].strip()

    if not token:
        raise HTTPException(status_code=401, detail="Authentication required.")

    token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
    record = (
        db.query(SessionToken)
        .filter(SessionToken.token_hash == token_hash, SessionToken.revoked.is_(False))
        .first()
    )
    if record is None or record.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=401, detail="Invalid or expired session.")

    user = db.query(User).filter(User.id == record.user_id).first()
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Authentication required.")
    return user


@app.get("/health")
def health():
    return {
        "status": "ok",
        "environment": settings.PAYPAL_MODE,
        "sandbox_mode": settings.PAYPAL_MODE == "sandbox",
    }


@app.post("/api/auth/login")
def login(payload: LoginRequest, response: Response, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid username or password.")

    token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=settings.SESSION_TOKEN_TTL_MINUTES)
    db.add(
        SessionToken(
            user_id=user.id,
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            expires_at=expires_at,
            revoked=False,
        )
    )
    db.commit()

    cookie_token, cookie_config = _build_session_cookie(token)
    response.set_cookie("session_token", cookie_token, **cookie_config)
    return {
        "status": "ok",
        "user": _user_payload(user),
        "message": "Dashboard authentication successful.",
    }


@app.get("/api/auth/me")
def get_current_user_payload(user: User = Depends(get_current_user)):
    return {"status": "ok", "user": _user_payload(user)}


@app.post("/api/auth/logout")
def logout(response: Response, request: Request, db: Session = Depends(get_db)):
    token = request.cookies.get("session_token")
    if token:
        token_hash = hashlib.sha256(token.encode("utf-8")).hexdigest()
        db.query(SessionToken).filter(SessionToken.token_hash == token_hash).update({"revoked": True})
        db.commit()
    response.delete_cookie("session_token")
    return {"status": "ok", "message": "Logged out."}


@app.get("/api/paypal/config-status")
def config_status(user: User = Depends(get_current_user)):
    configured = bool(settings.PAYPAL_CLIENT_ID and settings.PAYPAL_CLIENT_SECRET)
    return {
        "mode": settings.PAYPAL_MODE,
        "configured": configured,
        "missing": [
            key for key, value in {"PAYPAL_CLIENT_ID": settings.PAYPAL_CLIENT_ID, "PAYPAL_CLIENT_SECRET": settings.PAYPAL_CLIENT_SECRET}.items() if not value
        ],
        "status": "ready" if configured else "blocked",
        "message": "PayPal OAuth is unavailable until the backend receives valid sandbox credentials." if not configured else "PayPal Sandbox configuration is present.",
    }


@app.post("/api/paypal/import")
def import_transactions(
    start_date: str = Query(...),
    end_date: str = Query(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
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
def list_transactions(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
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
    user: User = Depends(get_current_user),
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
def get_transaction_detail(transaction_id: str, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    row = db.query(PayPalTransactionRecord).filter(PayPalTransactionRecord.paypal_transaction_id == transaction_id).first()
    if row is None:
        return {"status": "not_found", "found": False, "message": "No PayPal Sandbox transaction was found for the supplied transaction ID.", "transaction": None}
    return {"status": "ok", "found": True, "message": "PayPal Sandbox transaction found.", "transaction": serialize_transaction_row(row)}


@app.get("/api/paypal/alerts")
def list_alerts(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
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


@app.get("/api/paypal/webhook-events")
def list_webhook_events(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
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
def get_ai_explanation_for_alert(alert_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
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
def update_alert_status(alert_id: int, status: str = Query(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
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
def get_balance(user: User = Depends(get_current_user)):
    try:
        payload = fetch_account_balance()
        return {
            "status": "ok",
            "environment": settings.PAYPAL_MODE,
            "message": "Balance reporting data is available.",
            "payload": payload,
        }
    except PayPalPermissionError as exc:
        return {
            "status": "blocked",
            "permission_error": True,
            "message": str(exc),
            "payload": None,
        }
    except PayPalConfigError as exc:
        return {
            "status": "blocked",
            "permission_error": False,
            "message": str(exc),
            "payload": None,
        }


@app.get("/api/paypal/orders/{order_id}")
def get_order(order_id: str, user: User = Depends(get_current_user)):
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


@app.get("/api/paypal/captures/{capture_id}")
def get_capture(capture_id: str, user: User = Depends(get_current_user)):
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
