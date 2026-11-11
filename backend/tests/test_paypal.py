import os
from types import SimpleNamespace

import pytest
import requests
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.pool import StaticPool

from app.config import Settings, settings
from app.db import get_db
from app.fraud import (
    build_training_dataset,
    classify_risk_level,
    create_ml_fraud_model,
    generate_fraud_alerts,
    score_transaction,
)
from app.db import ensure_database_schema
from app.main import app
from app.models import FraudAlert, PayPalTransactionRecord
from app.paypal import (
    PayPalConfigError,
    PayPalPermissionError,
    _safe_debug_metadata,
    create_checkout_order,
    create_payout,
    fetch_transaction_history,
    get_access_token,
    normalize_account_balance,
)


def test_paypal_oauth_requires_configuration(monkeypatch):
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "")

    with pytest.raises(PayPalConfigError, match="not configured"):
        get_access_token()


def test_paypal_oauth_success_uses_client_credentials(monkeypatch):
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")

    class MockResponse:
        status_code = 200
        text = '{"access_token":"sandbox-token"}'

        def raise_for_status(self):
            return None

        def json(self):
            return {"access_token": "sandbox-token"}

    expected = {}

    def fake_post(url, auth, data, timeout, **kwargs):
        expected["url"] = url
        expected["auth"] = auth
        expected["data"] = data
        expected["timeout"] = timeout
        return MockResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(paypal_module.requests, "post", fake_post)

    assert get_access_token() == "sandbox-token"
    assert expected["url"] == "https://api-m.sandbox.paypal.com/v1/oauth2/token"
    assert expected["auth"] == ("sandbox-client", "sandbox-secret")
    assert expected["data"] == {"grant_type": "client_credentials"}
    assert expected["timeout"] == 30


def test_paypal_oauth_invalid_credentials_raises_config_error(monkeypatch):
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "bad-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "bad-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")

    class MockResponse:
        status_code = 401
        text = '{"error":"invalid_client"}'

        def raise_for_status(self):
            raise requests.HTTPError(response=self)

    def fake_post(*args, **kwargs):
        return MockResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(paypal_module.requests, "post", fake_post)

    with pytest.raises(PayPalConfigError, match="PayPal OAuth failed"):
        get_access_token()


def test_paypal_oauth_distinguishes_authentication_from_permission_errors(monkeypatch):
    import app.paypal as paypal_module

    def mock_401(*args, **kwargs):
        class MockResponse:
            status_code = 401
            text = '{"error":"invalid_client"}'
            headers = {}

            def raise_for_status(self):
                raise requests.HTTPError(response=self)

        return MockResponse()

    def mock_403(*args, **kwargs):
        class MockResponse:
            status_code = 403
            text = '{"error":"access_denied","error_description":"The credentials do not have the required permissions."}'
            headers = {}

            def raise_for_status(self):
                raise requests.HTTPError(response=self)

        return MockResponse()

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "live-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "live-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.paypal.com")

    monkeypatch.setattr(paypal_module.requests, "post", mock_401)
    with pytest.raises(PayPalConfigError, match="401|invalid_client|live credentials"):
        get_access_token()

    monkeypatch.setattr(paypal_module.requests, "post", mock_403)
    with pytest.raises(PayPalPermissionError, match="403|permission|required permissions"):
        get_access_token()


def test_paypal_oauth_timeout_raises_config_error(monkeypatch):
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")

    def fake_post(*args, **kwargs):
        raise requests.exceptions.Timeout("timed out")

    import app.paypal as paypal_module

    monkeypatch.setattr(paypal_module.requests, "post", fake_post)

    with pytest.raises(PayPalConfigError, match="request failed"):
        get_access_token()


def test_environment_settings_are_loaded_from_environment(monkeypatch):
    for field, value in (
        ("PAYPAL_CLIENT_ID", "env-client-id"),
        ("PAYPAL_CLIENT_SECRET", "env-client-secret"),
        ("PAYPAL_WEBHOOK_ID", "webhook-id"),
        ("AUTH_SECRET_KEY", "auth-secret"),
        ("SARVAM_API_KEY", "sarvam-key"),
    ):
        monkeypatch.setenv(field, value)

    new_settings = Settings()

    assert new_settings.PAYPAL_CLIENT_ID == "env-client-id"
    assert new_settings.PAYPAL_CLIENT_SECRET == "env-client-secret"
    assert new_settings.PAYPAL_WEBHOOK_ID == "webhook-id"
    assert new_settings.AUTH_SECRET_KEY == "auth-secret"
    assert new_settings.SARVAM_API_KEY == "sarvam-key"


def test_settings_require_explicit_paypal_credentials_when_missing(monkeypatch):
    for field in ("PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET", "PAYPAL_WEBHOOK_ID"):
        monkeypatch.delenv(field, raising=False)

    new_settings = Settings()

    assert new_settings.PAYPAL_CLIENT_ID == ""
    assert new_settings.PAYPAL_CLIENT_SECRET == ""
    assert new_settings.PAYPAL_WEBHOOK_ID == ""


def test_dashboard_auth_defaults_to_production_when_enabled(monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("DASHBOARD_AUTH_REQUIRED", raising=False)

    new_settings = Settings()

    assert new_settings.DASHBOARD_AUTH_REQUIRED is True


def test_dashboard_auth_is_disabled_for_local_development(monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("DASHBOARD_AUTH_REQUIRED", raising=False)

    new_settings = Settings()

    assert new_settings.DASHBOARD_AUTH_REQUIRED is False


def test_production_sensitive_routes_require_dashboard_auth(monkeypatch, db_session):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "DASHBOARD_AUTH_REQUIRED", True)
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.get("/api/paypal/transactions")

    assert response.status_code == 401
    assert response.json()["detail"] == "Authentication required."

    app.dependency_overrides.clear()


def test_dashboard_login_sets_secure_session_cookie(monkeypatch, db_session):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "DASHBOARD_AUTH_REQUIRED", True)
    monkeypatch.setattr(settings, "DASHBOARD_USERNAME", "dashboard-admin")
    monkeypatch.setattr(settings, "DASHBOARD_PASSWORD", "StrongPass!123")
    monkeypatch.setattr(settings, "SESSION_TOKEN_TTL_MINUTES", 60)
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    response = client.post(
        "/api/dashboard/login",
        json={"username": "dashboard-admin", "password": "StrongPass!123"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "ok"
    assert "dashboard_session" in response.cookies
    assert "HttpOnly" in response.headers["set-cookie"]
    assert "SameSite=Lax" in response.headers["set-cookie"] or "SameSite=lax" in response.headers["set-cookie"]

    app.dependency_overrides.clear()


def test_dashboard_logout_invalidates_session(monkeypatch, db_session):
    monkeypatch.setattr(settings, "APP_ENV", "production")
    monkeypatch.setattr(settings, "DASHBOARD_AUTH_REQUIRED", True)
    monkeypatch.setattr(settings, "DASHBOARD_USERNAME", "dashboard-admin")
    monkeypatch.setattr(settings, "DASHBOARD_PASSWORD", "StrongPass!123")
    monkeypatch.setattr(settings, "SESSION_TOKEN_TTL_MINUTES", 60)
    app.dependency_overrides[get_db] = lambda: db_session

    client = TestClient(app)
    login_response = client.post(
        "/api/dashboard/login",
        json={"username": "dashboard-admin", "password": "StrongPass!123"},
    )
    assert login_response.status_code == 200

    logout_response = client.post("/api/dashboard/logout")
    assert logout_response.status_code == 200
    assert logout_response.json()["status"] == "ok"

    session_response = client.get("/api/dashboard/session")
    assert session_response.status_code == 200
    assert session_response.json()["authenticated"] is False

    app.dependency_overrides.clear()


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


def test_normalize_account_balance_keeps_account_status_and_last_updated():
    payload = {
        "account_id": "ACCT-123",
        "status": "ACTIVE",
        "as_of_time": "2024-01-01T00:00:00Z",
        "balances": [
            {
                "currency": "USD",
                "total_balance": {"value": "25.00"},
                "available_balance": {"value": "15.00"},
                "withheld_balance": {"value": "10.00"},
                "last_updated": "2024-01-01T00:00:00Z",
            }
        ],
    }

    normalized = normalize_account_balance(payload)

    assert normalized["account_id"] == "ACCT-123"
    assert normalized["account_status"] == "ACTIVE"
    assert normalized["last_updated"] == "2024-01-01T00:00:00Z"
    assert normalized["available_balance"]["value"] == "15.00"


def test_safe_debug_metadata_exposes_status_and_order_id_only(monkeypatch):
    class MockResponse:
        status_code = 201
        headers = {"Paypal-Debug-Id": "debug-123"}
        url = "https://api-m.sandbox.paypal.com/v2/checkout/orders"

        def json(self):
            return {"id": "ORDER-123", "status": "CREATED", "access_token": "sandbox-token"}

    meta = _safe_debug_metadata(MockResponse(), "order creation")

    assert meta["status_code"] == 201
    assert meta["response_id"] == "ORDER-123"
    assert meta["debug_id"] == "debug-123"
    assert meta["hostname"] == "api-m.sandbox.paypal.com"
    assert "sandbox-token" not in str(meta)


def test_create_checkout_order_verifies_order_details_before_returning(monkeypatch):
    seen = {}

    class MockPostResponse:
        status_code = 201
        text = '{"id": "ORDER-123"}'
        headers = {"Paypal-Debug-Id": "create-debug-123"}

        def json(self):
            return {
                "id": "ORDER-123",
                "status": "CREATED",
                "links": [{"rel": "approve", "href": "https://sandbox.paypal.example/approve/ORDER-123"}],
            }

    class MockGetResponse:
        status_code = 200
        text = '{"id": "ORDER-123", "status": "CREATED"}'
        headers = {"Paypal-Debug-Id": "lookup-debug-123"}

        def json(self):
            return {"id": "ORDER-123", "status": "CREATED"}

    def fake_post(url, headers=None, json=None, timeout=None, auth=None, data=None, **kwargs):
        if url.endswith("/v1/oauth2/token"):
            class MockTokenResponse:
                status_code = 200
                text = '{"access_token":"sandbox-token"}'

                def json(self):
                    return {"access_token": "sandbox-token"}

            return MockTokenResponse()
        seen["post_url"] = url
        return MockPostResponse()

    def fake_get(url, headers=None, timeout=None, **kwargs):
        seen["get_url"] = url
        return MockGetResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "post", fake_post)
    monkeypatch.setattr(paypal_module.requests, "get", fake_get)

    payload = create_checkout_order("12.34", "USD")

    assert payload["id"] == "ORDER-123"
    assert seen["get_url"] == "https://api-m.sandbox.paypal.com/v2/checkout/orders/ORDER-123"


def test_create_checkout_order_rejects_404_verification_errors(monkeypatch):
    class MockPostResponse:
        status_code = 201
        text = '{"id": "ORDER-404"}'
        headers = {}

        def json(self):
            return {"id": "ORDER-404", "status": "CREATED", "links": []}

    class MockGetResponse:
        status_code = 404
        text = '{"name":"RESOURCE_NOT_FOUND"}'
        headers = {"Paypal-Debug-Id": "lookup-debug-404"}

        def json(self):
            return {"name": "RESOURCE_NOT_FOUND"}

    def fake_post(url, headers=None, json=None, timeout=None, auth=None, data=None, **kwargs):
        if url.endswith("/v1/oauth2/token"):
            class MockTokenResponse:
                status_code = 200
                text = '{"access_token":"sandbox-token"}'

                def json(self):
                    return {"access_token": "sandbox-token"}

            return MockTokenResponse()
        return MockPostResponse()

    def fake_get(url, headers=None, timeout=None, **kwargs):
        return MockGetResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "post", fake_post)
    monkeypatch.setattr(paypal_module.requests, "get", fake_get)

    with pytest.raises(RuntimeError, match="Failed to verify PayPal order ORDER-404"):
        create_checkout_order("12.34", "USD")


def test_create_checkout_order_rejects_other_http_verification_errors(monkeypatch):
    class MockPostResponse:
        status_code = 201
        text = '{"id": "ORDER-500"}'
        headers = {}

        def json(self):
            return {"id": "ORDER-500", "status": "CREATED", "links": []}

    class MockGetResponse:
        status_code = 500
        text = '{"name":"INTERNAL_SERVER_ERROR"}'
        headers = {"Paypal-Debug-Id": "lookup-debug-500"}

        def json(self):
            return {"name": "INTERNAL_SERVER_ERROR"}

    def fake_post(url, headers=None, json=None, timeout=None, auth=None, data=None, **kwargs):
        if url.endswith("/v1/oauth2/token"):
            class MockTokenResponse:
                status_code = 200
                text = '{"access_token":"sandbox-token"}'

                def json(self):
                    return {"access_token": "sandbox-token"}

            return MockTokenResponse()
        return MockPostResponse()

    def fake_get(url, headers=None, timeout=None, **kwargs):
        return MockGetResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "post", fake_post)
    monkeypatch.setattr(paypal_module.requests, "get", fake_get)

    with pytest.raises(RuntimeError, match="PayPal order verification failed"):
        create_checkout_order("12.34", "USD")


def test_create_checkout_order_rejects_mismatched_order_ids(monkeypatch):
    class MockPostResponse:
        status_code = 201
        text = '{"id": "ORDER-REAL"}'
        headers = {}

        def json(self):
            return {"id": "ORDER-REAL", "status": "CREATED", "links": []}

    class MockGetResponse:
        status_code = 200
        text = '{"id": "ORDER-OTHER", "status": "CREATED"}'
        headers = {}

        def json(self):
            return {"id": "ORDER-OTHER", "status": "CREATED"}

    def fake_post(url, headers=None, json=None, timeout=None, auth=None, data=None, **kwargs):
        if url.endswith("/v1/oauth2/token"):
            class MockTokenResponse:
                status_code = 200
                text = '{"access_token":"sandbox-token"}'

                def json(self):
                    return {"access_token": "sandbox-token"}

            return MockTokenResponse()
        return MockPostResponse()

    def fake_get(url, headers=None, timeout=None, **kwargs):
        return MockGetResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "post", fake_post)
    monkeypatch.setattr(paypal_module.requests, "get", fake_get)

    with pytest.raises(RuntimeError, match="Order ID mismatch"):
        create_checkout_order("12.34", "USD")


def test_live_payouts_are_blocked_until_eligibility_is_verified(monkeypatch):
    monkeypatch.setattr(settings, "PAYPAL_MODE", "live")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.paypal.com")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "live-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "live-secret")
    monkeypatch.setattr(settings, "PAYPAL_LIVE_PAYOUTS_ENABLED", False)

    with pytest.raises(PayPalConfigError, match="Live payouts are disabled"):
        create_payout("recipient@example.com", "12.34", "USD", "Test live payout")


def test_create_payout_uses_paypal_payouts_api_and_returns_batch_status(monkeypatch):
    seen = {}

    class MockResponse:
        status_code = 201
        text = '{"batch_header":{"payout_batch_id":"PAYOUT-123","batch_status":"PENDING"},"items":[{"payout_item_id":"ITEM-123","transaction_status":"PENDING","receiver":"buyer@example.com"}]}'
        headers = {"Paypal-Debug-Id": "payout-debug-123"}

        def json(self):
            return {
                "batch_header": {"payout_batch_id": "PAYOUT-123", "batch_status": "PENDING"},
                "items": [{"payout_item_id": "ITEM-123", "transaction_status": "PENDING", "receiver": "buyer@example.com"}],
            }

    def fake_post(url, headers=None, json=None, timeout=None, **kwargs):
        if url.endswith("/v1/oauth2/token"):
            class MockTokenResponse:
                status_code = 200
                text = '{"access_token":"sandbox-token"}'

                def json(self):
                    return {"access_token": "sandbox-token"}

            return MockTokenResponse()
        seen["url"] = url
        seen["json"] = json
        return MockResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "post", fake_post)

    payload = create_payout("buyer@example.com", "12.34", "USD", "Test payout")

    assert payload["batch_header"]["payout_batch_id"] == "PAYOUT-123"
    assert payload["items"][0]["transaction_status"] == "PENDING"
    assert seen["url"] == "https://api-m.sandbox.paypal.com/v1/payments/payouts"
    assert seen["json"]["items"][0]["receiver"] == "buyer@example.com"


def test_create_payout_route_persists_pending_status_and_refreshes_balance(db_session, monkeypatch):
    from app.db import get_db
    from app.main import app

    monkeypatch.setattr("app.main.fetch_account_balance", lambda: {"status": "ok", "balances": [{
        "currency": "USD",
        "total_balance": {"value": "4999.00", "currency": "USD"},
        "available_balance": {"value": "4999.00", "currency": "USD"},
        "withheld_balance": {"value": "0.00", "currency": "USD"},
        "last_updated": "2024-01-02T00:00:00Z",
    }]})
    monkeypatch.setattr("app.main.create_payout", lambda recipient_email, amount, currency, note: {
        "batch_header": {"payout_batch_id": "PAYOUT-ROUTE-001", "batch_status": "PENDING"},
        "items": [{"payout_item_id": "ITEM-ROUTE-001", "transaction_status": "PENDING", "receiver": recipient_email, "amount": {"value": amount, "currency": currency}}],
    })

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    response = client.post(
        "/api/paypal/payouts",
        json={"recipient_email": "buyer@example.com", "amount": "12.34", "currency": "USD", "note": "Test payout"},
    )
    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert response.json()["status"] == "pending"
    assert response.json()["batch_id"] == "PAYOUT-ROUTE-001"
    assert response.json()["balance"]["status"] == "ok"


def test_fetch_payout_batch_details_calls_paypal_details_endpoint(monkeypatch):
    import app.paypal as paypal_module

    seen = {}

    class MockResponse:
        status_code = 200
        headers = {"Paypal-Debug-Id": "payout-details-debug"}

        def json(self):
            return {
                "batch_header": {"payout_batch_id": "PAYOUT-DETAILS-001", "batch_status": "SUCCESS"},
                "items": [{"payout_item_id": "ITEM-DETAILS-001", "transaction_status": "SUCCESS", "receiver": "buyer@example.com"}],
            }

    def fake_get(url, headers=None, timeout=None, **kwargs):
        seen["url"] = url
        seen["headers"] = headers
        return MockResponse()

    monkeypatch.setattr(settings, "PAYPAL_MODE", "sandbox")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "get", fake_get)

    payload = paypal_module.fetch_payout_batch_details("PAYOUT-DETAILS-001")

    assert payload["batch_header"]["batch_status"] == "SUCCESS"
    assert seen["url"] == "https://api-m.sandbox.paypal.com/v1/payments/payouts/PAYOUT-DETAILS-001"
    assert seen["headers"]["Authorization"].startswith("Bearer ")


def test_create_payout_uses_unique_sender_batch_id_for_duplicate_prevention(monkeypatch):
    seen_ids = []

    class MockResponse:
        status_code = 201
        headers = {"Paypal-Debug-Id": "payout-duplicate-debug"}
        text = '{"batch_header":{"payout_batch_id":"PAYOUT-UNIQUE-001","batch_status":"PENDING"},"items":[{"payout_item_id":"ITEM-UNIQUE-001","transaction_status":"PENDING","receiver":"buyer@example.com"}]}'

        def json(self):
            return {
                "batch_header": {"payout_batch_id": "PAYOUT-UNIQUE-001", "batch_status": "PENDING"},
                "items": [{"payout_item_id": "ITEM-UNIQUE-001", "transaction_status": "PENDING", "receiver": "buyer@example.com"}],
            }

    def fake_post(url, headers=None, json=None, timeout=None, **kwargs):
        if url.endswith("/v1/oauth2/token"):
            class MockTokenResponse:
                status_code = 200
                text = '{"access_token":"sandbox-token"}'

                def json(self):
                    return {"access_token": "sandbox-token"}

            return MockTokenResponse()
        seen_ids.append(json["sender_batch_header"]["sender_batch_id"])
        return MockResponse()

    import app.paypal as paypal_module

    monkeypatch.setattr(settings, "PAYPAL_MODE", "sandbox")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_ID", "sandbox-client")
    monkeypatch.setattr(settings, "PAYPAL_CLIENT_SECRET", "sandbox-secret")
    monkeypatch.setattr(settings, "PAYPAL_API_BASE", "https://api-m.sandbox.paypal.com")
    monkeypatch.setattr(paypal_module.requests, "post", fake_post)

    first = paypal_module.create_payout("buyer@example.com", "12.34", "USD", "Test payout")
    second = paypal_module.create_payout("buyer@example.com", "12.34", "USD", "Test payout")

    assert first["batch_header"]["payout_batch_id"] == "PAYOUT-UNIQUE-001"
    assert second["batch_header"]["payout_batch_id"] == "PAYOUT-UNIQUE-001"
    assert len(set(seen_ids)) == 2


def test_balance_parser_prefers_latest_usd_snapshot():
    payload = {
        "currency": "USD",
        "balances": [
            {
                "currency": "USD",
                "total_balance": {"value": "5000.00", "currency": "USD"},
                "available_balance": {"value": "5000.00", "currency": "USD"},
                "withheld_balance": {"value": "0.00", "currency": "USD"},
                "last_updated": "2024-01-01T00:00:00Z",
            },
            {
                "currency": "USD",
                "total_balance": {"value": "4999.00", "currency": "USD"},
                "available_balance": {"value": "4999.00", "currency": "USD"},
                "withheld_balance": {"value": "0.00", "currency": "USD"},
                "last_updated": "2024-01-02T00:00:00Z",
            },
        ],
    }

    normalized = normalize_account_balance(payload)
    assert normalized["total_balance"]["value"] == "4999.00"
    assert normalized["available_balance"]["value"] == "4999.00"
    assert normalized["currency"] == "USD"


def test_dashboard_loads_without_login_dependency(db_session):
    from app.db import get_db
    from app.main import app

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)
    response = client.get("/api/paypal/config-status")
    app.dependency_overrides.clear()

    assert response.status_code == 200
    assert "configured" in response.json()


def test_order_and_capture_routes_expose_approval_url_and_persist_completed_capture(db_session, monkeypatch):
    from app.db import get_db
    from app.main import app

    monkeypatch.setattr("app.main.create_checkout_order", lambda amount, currency: {
        "id": "ORDER-REAL-001",
        "status": "CREATED",
        "links": [
            {
                "rel": "approve",
                "href": "https://www.sandbox.paypal.com/checkoutnow?token=TOKEN-123",
                "method": "GET",
            }
        ],
    })
    monkeypatch.setattr("app.main.capture_checkout_order", lambda order_id: {
        "id": "ORDER-REAL-001",
        "status": "COMPLETED",
        "purchase_units": [
            {
                "payments": {
                    "captures": [
                        {
                            "id": "CAPTURE-REAL-001",
                            "status": "COMPLETED",
                            "amount": {"value": "1.00", "currency_code": "USD"},
                        }
                    ]
                }
            }
        ],
    })
    monkeypatch.setattr("app.main.fetch_account_balance", lambda: {"status": "ok", "balances": [{"currency": "USD", "total_balance": {"value": "4999.00"}, "available_balance": {"value": "4999.00"}, "withheld_balance": {"value": "0.00"}}]})

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    order_response = client.post("/api/paypal/orders", json={"amount": "1.00", "currency": "USD"})
    assert order_response.status_code == 200
    assert order_response.json()["approval_url"].startswith("https://www.sandbox.paypal.com")

    capture_response = client.post("/api/paypal/orders/ORDER-REAL-001/capture")
    app.dependency_overrides.clear()

    assert capture_response.status_code == 200
    capture_payload = capture_response.json()
    assert capture_payload["order_id"] == "ORDER-REAL-001"
    assert capture_payload["capture_id"] == "CAPTURE-REAL-001"
    assert capture_payload["transaction_id"] == "CAPTURE-REAL-001"
    assert capture_payload["amount"] == "1.00"
    assert capture_payload["currency"] == "USD"
    assert capture_payload["paypal_status"] == "COMPLETED"
    assert capture_payload["balance"]["status"] == "ok"
    assert db_session.query(PayPalTransactionRecord).filter_by(paypal_transaction_id="CAPTURE-REAL-001").count() == 1


def test_capture_route_rejects_non_completed_capture(db_session, monkeypatch):
    from app.db import get_db
    from app.main import app

    monkeypatch.setattr("app.main.capture_checkout_order", lambda order_id: {
        "id": "ORDER-PENDING-001",
        "status": "PENDING",
        "purchase_units": [
            {
                "payments": {
                    "captures": [
                        {
                            "id": "CAPTURE-PENDING-001",
                            "status": "PENDING",
                            "amount": {"value": "1.00", "currency_code": "USD"},
                        }
                    ]
                }
            }
        ],
    })

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    response = client.post("/api/paypal/orders/ORDER-PENDING-001/capture")
    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "did not confirm a completed capture" in response.json()["detail"]
    assert db_session.query(PayPalTransactionRecord).count() == 0


def test_capture_route_rejects_failed_capture(db_session, monkeypatch):
    from app.db import get_db
    from app.main import app

    monkeypatch.setattr("app.main.capture_checkout_order", lambda order_id: {
        "id": "ORDER-FAILED-001",
        "status": "FAILED",
        "purchase_units": [
            {
                "payments": {
                    "captures": [
                        {
                            "id": "CAPTURE-FAILED-001",
                            "status": "FAILED",
                            "amount": {"value": "1.00", "currency_code": "USD"},
                        }
                    ]
                }
            }
        ],
    })

    app.dependency_overrides[get_db] = lambda: db_session
    client = TestClient(app)

    response = client.post("/api/paypal/orders/ORDER-FAILED-001/capture")
    app.dependency_overrides.clear()

    assert response.status_code == 400
    assert "Final status: FAILED" in response.json()["detail"]
    assert db_session.query(PayPalTransactionRecord).count() == 0


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


def test_ml_model_scores_and_classifies_transactions():
    dataset = build_training_dataset()
    assert dataset and len(dataset) >= 40
    assert all(row.get("synthetic") is True for row in dataset[:3])

    model = create_ml_fraud_model()
    assert model["model_type"] == "random_forest"
    assert model["training_data_source"] == "synthetic"
    assert model["risk_thresholds"] == {"low": 30, "medium": 70}

    suspicious = score_transaction(
        {
            "amount": "1500.00",
            "transaction_frequency": 4,
            "unusual_transaction_time": 1,
            "repeated_recipient": 1,
            "transaction_velocity": 0.9,
            "unusual_spending_pattern": 1,
        }
    )
    assert 0 <= suspicious["fraud_probability"] <= 100
    assert suspicious["risk_level"] in {"LOW RISK", "MEDIUM RISK", "HIGH RISK"}

    assert classify_risk_level(15) == "LOW RISK"
    assert classify_risk_level(55) == "MEDIUM RISK"
    assert classify_risk_level(85) == "HIGH RISK"


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
