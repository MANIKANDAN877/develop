from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import get_db
from app.fraud import generate_fraud_alerts
from app.db import ensure_database_schema
from app.main import app
from app.models import FraudAlert, PayPalTransactionRecord, User
from app.paypal import PayPalConfigError, PayPalPermissionError, fetch_transaction_history, get_access_token


def test_paypal_oauth_requires_configuration(monkeypatch):
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "")

    with pytest.raises(PayPalConfigError, match="not configured"):
        get_access_token()


def test_missing_reporting_permissions_are_exposed(monkeypatch):
    class PermissionResponse:
        status_code = 403
        text = '{"name":"AUTHORIZATION_ERROR"}'
        headers = {"Content-Type": "application/json"}

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")

    def fake_post(*args, **kwargs):
        return SimpleNamespace(status_code=200, json=lambda: {"access_token": "sandbox-token"})

    def fake_get(*args, **kwargs):
        return PermissionResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(paypal_module.requests, "post", fake_post)
    monkeypatch.setattr(paypal_module.requests, "get", fake_get)

    with pytest.raises(PayPalPermissionError, match="permission is unavailable"):
        fetch_transaction_history("2024-01-01T00:00:00Z", "2024-01-31T00:00:00Z")


def test_duplicate_transaction_prevention(db_session):
    first = PayPalTransactionRecord(
        paypal_transaction_id="TXN-duplicate-001",
        payer_email="buyer@example.com",
        amount="10.00",
        currency="USD",
        transaction_status="completed",
        source_reference="/v1/reporting/transactions",
        environment="sandbox",
    )
    db_session.add(first)
    db_session.commit()

    repeated = db_session.query(PayPalTransactionRecord).filter_by(paypal_transaction_id="TXN-duplicate-001").first()
    assert repeated is not None
    assert repeated.paypal_transaction_id == "TXN-duplicate-001"


def test_fraud_alert_generation_uses_review_only():
    records = [
        {
            "paypal_transaction_id": "TXN-ALERT-1",
            "payer_email": "buyer@example.com",
            "amount": "5000",
            "currency": "USD",
            "transaction_status": "failed",
            "created_at": "2024-01-01T12:00:00Z",
        },
        {
            "paypal_transaction_id": "TXN-ALERT-2",
            "payer_email": "buyer@example.com",
            "amount": "5001",
            "currency": "USD",
            "transaction_status": "failed",
            "created_at": "2024-01-01T12:10:00Z",
        },
    ]

    alerts = generate_fraud_alerts(records)
    assert alerts
    assert all(alert.get("status") == "review" for alert in alerts)
    assert not any("confirmed fraud" in str(alert.get("message", "")).lower() for alert in alerts)


def test_fraud_detection_rules_cover_normal_and_suspicious_cases():
    normal_records = [
        {
            "paypal_transaction_id": "TXN-NORMAL-1",
            "payer_email": "buyer@example.com",
            "amount": "100.00",
            "currency": "USD",
            "transaction_status": "S",
            "created_at": "2024-01-01T12:00:00Z",
        }
    ]
    assert generate_fraud_alerts(normal_records) == []

    large_records = [
        {
            "paypal_transaction_id": "TXN-LARGE-1",
            "payer_email": "buyer@example.com",
            "amount": "2500.00",
            "currency": "USD",
            "transaction_status": "S",
            "created_at": "2024-01-01T12:00:00Z",
        }
    ]
    large_alerts = generate_fraud_alerts(large_records)
    assert any(alert["alert_type"] == "unusual_amount" for alert in large_alerts)

    repeated_records = [
        {
            "paypal_transaction_id": "TXN-DUP-1",
            "payer_email": "buyer@example.com",
            "amount": "120.00",
            "currency": "USD",
            "transaction_status": "S",
            "created_at": "2024-01-01T12:00:00Z",
        },
        {
            "paypal_transaction_id": "TXN-DUP-2",
            "payer_email": "buyer@example.com",
            "amount": "120.00",
            "currency": "USD",
            "transaction_status": "S",
            "created_at": "2024-01-01T12:10:00Z",
        },
    ]
    duplicate_alerts = generate_fraud_alerts(repeated_records)
    assert any(alert["alert_type"] == "duplicate_payment" for alert in duplicate_alerts)

    suspicious_records = [
        {
            "paypal_transaction_id": "TXN-SUSP-1",
            "payer_email": "buyer@example.com",
            "amount": "600.00",
            "currency": "USD",
            "transaction_status": "failed",
            "created_at": "2024-01-01T12:00:00Z",
        },
        {
            "paypal_transaction_id": "TXN-SUSP-2",
            "payer_email": "buyer@example.com",
            "amount": "750.00",
            "currency": "USD",
            "transaction_status": "failed",
            "created_at": "2024-01-01T12:05:00Z",
        },
    ]
    suspicious_alerts = generate_fraud_alerts(suspicious_records)
    assert any(
        alert["alert_type"] in {"repeated_failed_payment", "suspicious_payment_pattern"}
        for alert in suspicious_alerts
    )


def test_search_transaction_by_paypal_id(db_session):
    db_session.add(
        PayPalTransactionRecord(
            paypal_transaction_id="TXN-SRCH-42",
            payer_email="buyer@example.com",
            amount="125.50",
            currency="USD",
            transaction_status="S",
            payment_status="S",
            source_reference="/v1/reporting/transactions",
            environment="sandbox",
        )
    )
    db_session.commit()

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    response = client.get("/api/paypal/transactions/search", params={"transaction_id": "TXN-SRCH-42"})
    app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["transaction"]["paypal_transaction_id"] == "TXN-SRCH-42"
    assert payload["transaction"]["amount"] == "125.50"


def test_transaction_search_filters_and_alert_review_update(db_session):
    db_session.add_all(
        [
            PayPalTransactionRecord(
                paypal_transaction_id="TXN-FILTER-1",
                payer_email="buyer@example.com",
                parent_transaction_id="ORDER-100",
                amount="250.00",
                currency="USD",
                transaction_status="S",
                payment_status="S",
                source_reference="/v1/reporting/transactions",
                environment="sandbox",
            ),
            PayPalTransactionRecord(
                paypal_transaction_id="TXN-FILTER-2",
                payer_email="buyer@example.com",
                parent_transaction_id="ORDER-200",
                amount="500.00",
                currency="USD",
                transaction_status="P",
                payment_status="P",
                source_reference="/v1/reporting/transactions",
                environment="sandbox",
            ),
        ]
    )
    db_session.commit()

    alert = FraudAlert(
        paypal_transaction_id="TXN-FILTER-1",
        alert_type="unusual_amount",
        severity="high",
        message="Review required: transaction amount is materially higher than the median in the retrieved dataset.",
        evidence={"amount": "250.00"},
        source_reference="/v1/reporting/transactions",
        status="review",
    )
    db_session.add(alert)
    db_session.commit()

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    search_response = client.get(
        "/api/paypal/transactions/search",
        params={"order_id": "ORDER-100", "amount": "250.00", "payment_status": "S"},
    )
    assert search_response.status_code == 200
    search_payload = search_response.json()
    assert search_payload["found"] is True
    assert search_payload["transaction"]["paypal_transaction_id"] == "TXN-FILTER-1"

    patch_response = client.patch(
        f"/api/paypal/alerts/{alert.id}",
        params={"status": "resolved"},
    )
    app.dependency_overrides.clear()
    assert patch_response.status_code == 200
    payload = patch_response.json()
    assert payload["status"] == "resolved"
    assert payload["alert_id"] == alert.id


def test_database_schema_migration_adds_missing_columns():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    with engine.begin() as conn:
        conn.execute(
            text(
                "CREATE TABLE paypal_transactions (id INTEGER PRIMARY KEY, paypal_transaction_id VARCHAR UNIQUE, payer_email VARCHAR, amount VARCHAR, currency VARCHAR, transaction_status VARCHAR, source_reference VARCHAR, environment VARCHAR)"
            )
        )
        conn.execute(
            text(
                "CREATE TABLE fraud_alerts (id INTEGER PRIMARY KEY, paypal_transaction_id VARCHAR, alert_type VARCHAR, severity VARCHAR, message TEXT, status VARCHAR)"
            )
        )

    ensure_database_schema(engine)

    inspector = inspect(engine)
    paypal_columns = {column["name"] for column in inspector.get_columns("paypal_transactions")}
    alert_columns = {column["name"] for column in inspector.get_columns("fraud_alerts")}

    assert "order_id" in paypal_columns
    assert "risk_score" in alert_columns


def test_sarvam_explanation_payload_excludes_pii(monkeypatch):
    import app.sarvam as sarvam_module

    payload = {
        "paypal_transaction_id": "TXN-SARVAM-1",
        "payer_email": "customer@example.com",
        "amount": "2500.00",
        "currency": "USD",
        "transaction_status": "failed",
        "payment_status": "failed",
        "environment": "sandbox",
        "source_reference": "/v1/reporting/transactions",
        "created_at": "2024-01-01T12:00:00Z",
    }
    alert = {
        "alert_type": "unusual_amount",
        "severity": "high",
        "risk_score": 92,
        "message": "Review required: transaction amount is materially higher than the median in the retrieved dataset.",
        "evidence": {"amount": "2500.00", "median_amount": 120.0},
        "status": "review",
    }

    class DummyResponse:
        status_code = 200

        def json(self):
            return {
                "choices": [{"message": {"content": '{"explanation": "High-value failed payment.", "risk_factors": ["amount exceeds median"], "recommended_action": "Manual review", "ai_model": "sarvam-105b"}'}}]
            }

    monkeypatch.setattr(sarvam_module.requests, "post", lambda *args, **kwargs: DummyResponse())
    monkeypatch.setattr(sarvam_module.settings, "SARVAM_API_KEY", "test-key")
    monkeypatch.setattr(sarvam_module.settings, "APP_ENV", "development")

    result = sarvam_module.generate_ai_explanation(alert, payload)

    assert result["ai_model"] == "sarvam-105b"
    assert result["risk_factors"]
    assert "customer@example.com" not in str(result)
    assert "api_key" not in str(result).lower()


def test_health_endpoint():
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "ok"
    assert payload["environment"] in {"sandbox", "production"}


def test_login_route_success_and_invalid_credentials(db_session):
    from app.main import hash_password

    db_session.add(User(username="secure-user", password_hash=hash_password("S3curePass!")))
    db_session.commit()

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    success = client.post("/api/auth/login", json={"username": "secure-user", "password": "S3curePass!"})
    assert success.status_code == 200
    assert success.json()["status"] == "ok"
    assert success.cookies.get("session_token")

    failure = client.post("/api/auth/login", json={"username": "secure-user", "password": "wrong-pass"})
    assert failure.status_code == 401
    assert failure.json()["detail"] == "Invalid username or password."
    app.dependency_overrides.clear()


def test_ai_explanation_endpoint_returns_unavailable_when_sarvam_fails(monkeypatch, db_session):
    from app.main import app
    from app.db import get_db

    alert = FraudAlert(
        paypal_transaction_id="TXN-AI-FAIL",
        alert_type="duplicate_payment",
        severity="medium",
        risk_score=66,
        message="Review required: repeated payment with the same payer and amount detected.",
        evidence={"payer_email": "masked@example.com", "amount": "120.00"},
        source_reference="/v1/reporting/transactions",
        status="review",
    )
    db_session.add(alert)
    db_session.commit()

    db_session.add(
        PayPalTransactionRecord(
            paypal_transaction_id="TXN-AI-FAIL",
            payer_email="masked@example.com",
            amount="120.00",
            currency="USD",
            transaction_status="failed",
            payment_status="failed",
            source_reference="/v1/reporting/transactions",
            environment="sandbox",
        )
    )
    db_session.commit()

    import app.sarvam as sarvam_module

    class FakeHttpErrorResponse:
        status_code = 403

        def json(self):
            return {"error": {"message": "Invalid or expired API key"}}

        text = '{"error":{"message":"Invalid or expired API key"}}'

    monkeypatch.setattr(sarvam_module.settings, "APP_ENV", "development")
    monkeypatch.setattr(sarvam_module.settings, "SARVAM_API_KEY", "test-key")
    monkeypatch.setattr(sarvam_module.requests, "post", lambda *args, **kwargs: FakeHttpErrorResponse())

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    response = client.post(f"/api/paypal/alerts/{alert.id}/ai-explanation")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    payload = response.json()
    assert payload["status"] == "unavailable"
    assert payload["ai_model"] == "sarvam-105b"
    assert payload["provider_status"] == 403
    assert "Invalid or expired API key" in payload["provider_error"]
    assert payload["explanation"] == "AI explanation unavailable."


def test_paypal_webhook_valid_signature_is_stored_and_processed(monkeypatch, db_session):
    from app.db import get_db
    from app.main import app

    payload = {
        "id": "WH-VALID-001",
        "event_version": "1.0",
        "create_time": "2024-01-01T00:00:00Z",
        "resource_type": "capture",
        "event_type": "PAYMENT.CAPTURE.COMPLETED",
        "resource": {
            "id": "CAPTURE-VALID-001",
            "amount": {"value": "250.00", "currency_code": "USD"},
            "status": "COMPLETED",
            "parent_payment": "PAYMENT-VALID-001",
        },
        "summary": "Payment completed.",
    }

    class VerificationResponse:
        status_code = 200

        def json(self):
            return {"verification_status": "SUCCESS"}

    monkeypatch.setattr("app.main.settings.PAYPAL_WEBHOOK_ID", "WH-VALID-ID")
    monkeypatch.setattr("app.main.requests.post", lambda *args, **kwargs: VerificationResponse())

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    response = client.post(
        "/api/paypal/webhooks",
        json=payload,
        headers={
            "PayPal-Transmission-Id": "txn-1",
            "PayPal-Transmission-Time": "2024-01-01T00:00:00Z",
            "PayPal-Cert-Url": "https://example.com/cert.pem",
            "PayPal-Transmission-Sig": "signature-1",
        },
    )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "received"
    assert db_session.query(PayPalTransactionRecord).filter_by(paypal_transaction_id="CAPTURE-VALID-001").count() == 1


def test_paypal_webhook_invalid_signature_is_rejected(monkeypatch, db_session):
    from app.db import get_db
    from app.main import app

    payload = {
        "id": "WH-INVALID-001",
        "event_type": "PAYMENT.CAPTURE.DENIED",
        "resource": {"id": "CAPTURE-INVALID-001", "amount": {"value": "50.00", "currency_code": "USD"}, "status": "DENIED"},
    }

    class VerificationResponse:
        status_code = 200

        def json(self):
            return {"verification_status": "FAILURE"}

    monkeypatch.setattr("app.main.settings.PAYPAL_WEBHOOK_ID", "WH-VALID-ID")
    monkeypatch.setattr("app.main.requests.post", lambda *args, **kwargs: VerificationResponse())

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    response = client.post(
        "/api/paypal/webhooks",
        json=payload,
        headers={
            "PayPal-Transmission-Id": "txn-2",
            "PayPal-Transmission-Time": "2024-01-01T00:00:00Z",
            "PayPal-Cert-Url": "https://example.com/cert.pem",
            "PayPal-Transmission-Sig": "signature-2",
        },
    )
    app.dependency_overrides.clear()

    assert response.status_code == 401
    assert db_session.query(PayPalTransactionRecord).filter_by(paypal_transaction_id="CAPTURE-INVALID-001").count() == 0


def test_paypal_webhook_duplicate_event_is_not_processed_twice(monkeypatch, db_session):
    from app.db import get_db
    from app.main import app

    payload = {
        "id": "WH-DUPLICATE-001",
        "event_type": "PAYMENT.CAPTURE.REFUNDED",
        "resource": {"id": "CAPTURE-DUP-001", "amount": {"value": "90.00", "currency_code": "USD"}, "status": "REFUNDED"},
    }

    class VerificationResponse:
        status_code = 200

        def json(self):
            return {"verification_status": "SUCCESS"}

    monkeypatch.setattr("app.main.settings.PAYPAL_WEBHOOK_ID", "WH-VALID-ID")
    monkeypatch.setattr("app.main.requests.post", lambda *args, **kwargs: VerificationResponse())

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    first = client.post(
        "/api/paypal/webhooks",
        json=payload,
        headers={
            "PayPal-Transmission-Id": "txn-3",
            "PayPal-Transmission-Time": "2024-01-01T00:00:00Z",
            "PayPal-Cert-Url": "https://example.com/cert.pem",
            "PayPal-Transmission-Sig": "signature-3",
        },
    )
    second = client.post(
        "/api/paypal/webhooks",
        json=payload,
        headers={
            "PayPal-Transmission-Id": "txn-4",
            "PayPal-Transmission-Time": "2024-01-01T00:00:00Z",
            "PayPal-Cert-Url": "https://example.com/cert.pem",
            "PayPal-Transmission-Sig": "signature-4",
        },
    )
    app.dependency_overrides.clear()

    assert first.status_code == 200
    assert second.status_code == 200
    assert second.json()["duplicate"] is True
    assert db_session.query(PayPalTransactionRecord).filter_by(paypal_transaction_id="CAPTURE-DUP-001").count() == 1
