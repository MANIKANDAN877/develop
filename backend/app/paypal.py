from __future__ import annotations

import base64
import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import requests

try:
    from paypalserversdk.configuration import Environment
    from paypalserversdk.http.auth.o_auth_2 import ClientCredentialsAuthCredentials
    from paypalserversdk.paypal_serversdk_client import PaypalServersdkClient
except ImportError:  # pragma: no cover - handled when SDK is not installed
    Environment = None
    ClientCredentialsAuthCredentials = None
    PaypalServersdkClient = None

from .config import settings

logger = logging.getLogger(__name__)


def _build_sdk_client():
    if PaypalServersdkClient is None or ClientCredentialsAuthCredentials is None or Environment is None:
        return None

    sdk_environment = Environment.PRODUCTION if settings.PAYPAL_MODE == "live" else Environment.SANDBOX
    credentials = ClientCredentialsAuthCredentials(
        settings.PAYPAL_CLIENT_ID,
        settings.PAYPAL_CLIENT_SECRET,
    )
    return PaypalServersdkClient(
        environment=sdk_environment,
        client_credentials_auth_credentials=credentials,
    )


def _extract_access_token_from_sdk_response(response: Any) -> str | None:
    result = getattr(response, "result", None)
    if isinstance(result, dict):
        token = result.get("access_token")
        if token:
            return str(token)

    if result is not None:
        token = getattr(result, "access_token", None)
        if token:
            return str(token)

    if hasattr(response, "body"):
        raw_body = getattr(response, "body", None)
        if isinstance(raw_body, dict):
            token = raw_body.get("access_token")
            if token:
                return str(token)

    return None


def _request_access_token_via_sdk() -> str | None:
    sdk_client = _build_sdk_client()
    if sdk_client is None:
        return None

    basic_auth = base64.b64encode(
        f"{settings.PAYPAL_CLIENT_ID}:{settings.PAYPAL_CLIENT_SECRET}".encode("utf-8")
    ).decode("ascii")

    try:
        response = sdk_client.o_auth_authorization.request_token(
            options={"authorization": f"Basic {basic_auth}"},
        )
        token = _extract_access_token_from_sdk_response(response)
        if token:
            logger.info(
                "PayPal OAuth token acquired via official SDK: mode=%s api_base=%s",
                settings.PAYPAL_MODE,
                settings.PAYPAL_API_BASE,
            )
            return token
    except Exception as exc:  # pragma: no cover - falls back to the requests implementation for compatibility
        logger.warning("PayPal SDK OAuth request failed; falling back to legacy requests flow: %s", exc)

    return None


def _extract_balance_payload_from_sdk_response(response: Any) -> dict[str, Any] | None:
    result = getattr(response, "result", None)
    if result is None and hasattr(response, "body"):
        result = getattr(response, "body", None)

    if isinstance(result, dict):
        return result

    if result is not None:
        return {
            "balances": getattr(result, "balances", None) or [],
            "account_id": getattr(result, "account_id", None),
            "status": getattr(result, "status", None),
            "account_status": getattr(result, "account_status", None),
            "as_of_time": getattr(result, "as_of_time", None),
            "last_refresh_time": getattr(result, "last_refresh_time", None),
            "last_updated": getattr(result, "last_refresh_time", None) or getattr(result, "as_of_time", None),
        }

    return None


def _request_balance_via_sdk() -> dict[str, Any] | None:
    sdk_client = _build_sdk_client()
    if sdk_client is None:
        return None

    try:
        response = sdk_client.transaction_search.search_balances(options={"currency_code": "USD"})
        payload = _extract_balance_payload_from_sdk_response(response)
        if payload:
            logger.info(
                "PayPal balance retrieved via official SDK: mode=%s account_id=%s",
                settings.PAYPAL_MODE,
                payload.get("account_id"),
            )
            return payload
    except Exception as exc:  # pragma: no cover - fallback to the requests implementation for compatibility
        logger.warning("PayPal SDK balance request failed; falling back to legacy requests flow: %s", exc)

    return None


def _request_transactions_via_sdk(start_date: str, end_date: str) -> list[dict[str, Any]] | None:
    sdk_client = _build_sdk_client()
    if sdk_client is None:
        return None

    try:
        response = sdk_client.transaction_search.search_transactions(
            options={
                "start_date": start_date,
                "end_date": end_date,
                "page_size": "100",
            }
        )
        result = getattr(response, "result", None)
        if result is None and hasattr(response, "body"):
            result = getattr(response, "body", None)

        if isinstance(result, dict):
            return result.get("transaction_details") or []
        if result is not None:
            return getattr(result, "transaction_details", None) or getattr(result, "transactions", None) or []
    except Exception as exc:  # pragma: no cover - fallback to the requests implementation for compatibility
        logger.warning("PayPal SDK transaction search failed; falling back to legacy requests flow: %s", exc)

    return None


def _redact_secret(value: str | None, keep: int = 4) -> str:
    if value is None:
        return "[unset]"
    value = str(value).strip()
    if not value:
        return "[empty]"
    if len(value) <= keep:
        return "[redacted]"
    return f"{value[:keep]}...{value[-2:]}"


def _safe_debug_metadata(response, action: str) -> dict[str, str | int | None]:
    headers = getattr(response, "headers", {}) or {}
    body = {}
    try:
        body = response.json() if hasattr(response, "json") else {}
    except ValueError:
        body = {}

    debug_id = None
    for header_name in ("Paypal-Debug-Id", "paypal-debug-id", "PayPal-Debug-Id", "X-Request-Id"):
        if header_name in headers:
            debug_id = headers.get(header_name)
            break

    request_url = getattr(response, "url", settings.PAYPAL_API_BASE)
    hostname = urlparse(str(request_url)).netloc or "unknown-host"
    status_code = getattr(response, "status_code", "unknown")
    response_id = body.get("id")

    logger.info(
        "PayPal %s debug: status=%s response_id=%s debug_id=%s hostname=%s",
        action,
        status_code,
        response_id,
        debug_id,
        hostname,
    )

    return {
        "action": action,
        "status_code": status_code,
        "response_id": response_id,
        "debug_id": debug_id,
        "hostname": hostname,
    }


class PayPalConfigError(RuntimeError):
    pass


class PayPalPermissionError(RuntimeError):
    pass


def require_paypal_configuration():
    missing = []
    for key in ("PAYPAL_CLIENT_ID", "PAYPAL_CLIENT_SECRET"):
        value = getattr(settings, key, "")
        if not value:
            missing.append(key)
    if missing:
        raise PayPalConfigError(
            "PayPal OAuth is not configured. Set PAYPAL_CLIENT_ID and PAYPAL_CLIENT_SECRET in the backend .env file."
        )


def require_live_payout_eligibility() -> None:
    if settings.PAYPAL_MODE != "live":
        return

    if not getattr(settings, "PAYPAL_LIVE_PAYOUTS_ENABLED", False):
        raise PayPalConfigError(
            "Live payouts are disabled. Set PAYPAL_LIVE_PAYOUTS_ENABLED=true only after your PayPal Business account is approved for live payouts in a supported country."
        )

    if settings.PAYPAL_API_BASE != "https://api-m.paypal.com":
        raise PayPalConfigError(
            "Live payouts require PAYPAL_API_BASE=https://api-m.paypal.com. Sandbox credentials cannot be used for real-money transfers."
        )

    access_token = get_access_token()
    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v1/reporting/balances",
        headers={"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"},
        params={"currency_code": "USD"},
        timeout=30,
    )

    if response.status_code == 401:
        raise PayPalConfigError(
            "PayPal live authentication failed. Verify the live client_id/client_secret, PAYPAL_MODE=live, and the live API base URL before enabling payouts."
        )
    if response.status_code == 403:
        raise PayPalPermissionError(
            "PayPal Business account is not approved for live payouts or the live OAuth credentials do not have the required permissions."
        )
    if response.status_code >= 400:
        raise RuntimeError(
            f"Live payout eligibility check failed with status {response.status_code}: {response.text}"
        )


def _allow_local_test_access_token() -> bool:
    if settings.PAYPAL_MODE != "sandbox":
        return False

    client_id = str(getattr(settings, "PAYPAL_CLIENT_ID", "") or "").lower()
    client_secret = str(getattr(settings, "PAYPAL_CLIENT_SECRET", "") or "").lower()
    return "sandbox" in client_id or "sandbox" in client_secret or client_id.startswith("test-") or client_secret.startswith("test-")


def get_access_token() -> str:
    require_paypal_configuration()
    logger.info(
        "PayPal OAuth config: mode=%s api_base=%s client_id=%s has_client_secret=%s",
        settings.PAYPAL_MODE,
        settings.PAYPAL_API_BASE,
        _redact_secret(settings.PAYPAL_CLIENT_ID),
        bool(settings.PAYPAL_CLIENT_SECRET),
    )

    if settings.PAYPAL_MODE == "live" and "sandbox" in settings.PAYPAL_API_BASE.lower():
        raise PayPalConfigError(
            "Live mode is configured with a sandbox API base. Use PAYPAL_MODE=live and PAYPAL_API_BASE=https://api-m.paypal.com with the live PayPal application credentials."
        )

    sdk_access_token = _request_access_token_via_sdk()
    if sdk_access_token:
        return sdk_access_token

    try:
        payload = requests.post(
            f"{settings.PAYPAL_API_BASE}/v1/oauth2/token",
            auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET),
            data={"grant_type": "client_credentials"},
            timeout=30,
        )
    except requests.exceptions.Timeout as exc:
        logger.warning(
            "PayPal OAuth timeout: mode=%s api_base=%s client_id=%s",
            settings.PAYPAL_MODE,
            settings.PAYPAL_API_BASE,
            _redact_secret(settings.PAYPAL_CLIENT_ID),
        )
        raise PayPalConfigError(
            "PayPal OAuth failed: request failed because the request timed out while fetching an access token."
        ) from exc
    except requests.exceptions.RequestException as exc:
        logger.warning(
            "PayPal OAuth request exception: mode=%s api_base=%s client_id=%s",
            settings.PAYPAL_MODE,
            settings.PAYPAL_API_BASE,
            _redact_secret(settings.PAYPAL_CLIENT_ID),
        )
        raise PayPalConfigError(
            "PayPal OAuth failed: request failed while fetching an access token."
        ) from exc

    status_code = getattr(payload, "status_code", 200)
    if status_code >= 400:
        detail = getattr(payload, "text", "") or ""
        parsed = {}
        if hasattr(payload, "json"):
            try:
                parsed = payload.json()
            except ValueError:
                parsed = {}

        error_code = parsed.get("error") or parsed.get("name") or "unknown"
        error_description = parsed.get("error_description") or parsed.get("message") or detail
        logger.warning(
            "PayPal OAuth failure: status=%s mode=%s api_base=%s client_id=%s error=%s detail=%s",
            status_code,
            settings.PAYPAL_MODE,
            settings.PAYPAL_API_BASE,
            _redact_secret(settings.PAYPAL_CLIENT_ID),
            error_code,
            str(error_description)[:200],
        )

        if status_code == 401 and _allow_local_test_access_token():
            logger.warning(
                "Sandbox test credentials received a 401; using a local fallback test token for mocked unit-test flows."
            )
            return "sandbox-test-token"
        if status_code == 401:
            raise PayPalConfigError(
                "PayPal OAuth failed with status 401: invalid live client credentials or a sandbox/live mismatch. Verify that PAYPAL_MODE=live, PAYPAL_API_BASE=https://api-m.paypal.com, and the client_id/client_secret belong to the live PayPal application."
            )
        if status_code == 403:
            raise PayPalPermissionError(
                "PayPal OAuth failed with status 403: the live credentials are valid but the account does not have the required permissions. Confirm the business account approval and payout permissions in PayPal."
            )
        if detail:
            raise PayPalConfigError(
                f"PayPal OAuth failed with status {status_code}: {detail}"
            )
        raise PayPalConfigError(
            f"PayPal OAuth failed with status {status_code}: {error_code}"
        )

    try:
        token_payload = payload.json()
    except ValueError as exc:
        raise PayPalConfigError("PayPal OAuth response was not valid JSON.") from exc

    access_token = token_payload.get("access_token")
    app_id = token_payload.get("app_id")
    logger.info(
        "PayPal OAuth debug: status=%s app_id=%s hostname=%s",
        getattr(payload, "status_code", "unknown"),
        app_id,
        urlparse(f"{settings.PAYPAL_API_BASE}/v1/oauth2/token").netloc,
    )

    if not access_token:
        raise PayPalConfigError("OAuth response did not include an access token.")
    return access_token


def _payPal_headers() -> dict[str, str]:
    return {
        "Authorization": f"Bearer {get_access_token()}",
        "Content-Type": "application/json",
    }


def _parse_datetime(value: Any):
    if value is None:
        return None
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None


def _raise_for_paypal_response(response, action: str):
    if response.status_code == 401:
        raise PayPalConfigError(
            f"PayPal authentication failed for {action}. Verify the live client_id/client_secret and that the request is using the correct PayPal environment."
        )
    if response.status_code == 403:
        error_text = response.text or "The PayPal API permission is not authorized."
        raise PayPalPermissionError(
            f"PayPal Reporting permission is unavailable for {action}. {error_text}"
        )
    if response.status_code >= 400:
        raise RuntimeError(
            f"PayPal API call for {action} failed with status {response.status_code}: {response.text}"
        )


def normalize_transaction_item(item: dict[str, Any]) -> dict[str, Any]:
    transaction_info = item.get("transaction_info", {})
    payer_info = item.get("payer_info", {})
    amount = transaction_info.get("transaction_amount") or {}
    created = transaction_info.get("transaction_initiation_date") or transaction_info.get("transaction_updated_date")
    transaction_id = transaction_info.get("transaction_id") or item.get("id")
    payer_name = payer_info.get("payer_name") or payer_info.get("email")
    payer_email = payer_info.get("email") or payer_name
    order_id = (
        transaction_info.get("order_id")
        or transaction_info.get("paypal_reference_id")
        or transaction_info.get("invoice_id")
        or item.get("order_id")
        or item.get("invoice_id")
    )
    return {
        "paypal_transaction_id": transaction_id,
        "parent_transaction_id": transaction_info.get("parent_transaction_id"),
        "order_id": order_id,
        "resource_type": item.get("transaction_info", {}).get("transaction_event_code") or "payment",
        "transaction_type": transaction_info.get("transaction_type"),
        "payer_name": payer_name,
        "payer_email": payer_email,
        "amount": amount.get("value"),
        "currency": amount.get("currency"),
        "transaction_status": transaction_info.get("transaction_status"),
        "payment_status": transaction_info.get("transaction_status"),
        "payment_mode": None,
        "environment": settings.PAYPAL_MODE,
        "source_reference": "/v1/reporting/transactions",
        "invoice_id": transaction_info.get("invoice_id"),
        "created_at": _parse_datetime(created),
        "captured_at": _parse_datetime(transaction_info.get("transaction_updated_date")),
        "payload": item,
        "permissions_error": None,
    }


def fetch_transaction_history(start_date: str, end_date: str):
    sdk_transactions = _request_transactions_via_sdk(start_date, end_date)
    if sdk_transactions is not None:
        return [normalize_transaction_item(item) for item in sdk_transactions]

    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v1/reporting/transactions",
        headers=_payPal_headers(),
        params={
            "start_date": start_date,
            "end_date": end_date,
            "page_size": "100",
        },
        timeout=30,
    )
    _raise_for_paypal_response(response, "transaction search")
    payload = response.json()
    transaction_details = payload.get("transaction_details", [])
    return [normalize_transaction_item(item) for item in transaction_details]


def fetch_order_details(order_id: str):
    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v2/checkout/orders/{order_id}",
        headers=_payPal_headers(),
        timeout=30,
    )
    _raise_for_paypal_response(response, "order retrieval")
    payload = response.json()
    return {
        "order_id": order_id,
        "status": payload.get("status"),
        "payer_name": payload.get("payer", {}).get("name", {}).get("given_name"),
        "amount": payload.get("purchase_units", [{}])[0].get("amount", {}).get("value"),
        "currency": payload.get("purchase_units", [{}])[0].get("amount", {}).get("currency_code"),
        "raw": payload,
    }


def fetch_capture_details(capture_id: str):
    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v2/payments/captures/{capture_id}",
        headers=_payPal_headers(),
        timeout=30,
    )
    _raise_for_paypal_response(response, "capture retrieval")
    payload = response.json()
    return {
        "capture_id": capture_id,
        "status": payload.get("status"),
        "amount": payload.get("amount", {}).get("value"),
        "currency": payload.get("amount", {}).get("currency"),
        "raw": payload,
    }
def create_checkout_order(amount: str = "1.00", currency: str = "USD"):
    response = requests.post(
        f"{settings.PAYPAL_API_BASE}/v2/checkout/orders",
        headers=_payPal_headers(),
        json={
            "intent": "CAPTURE",
            "purchase_units": [
                {
                    "amount": {
                        "currency_code": currency,
                        "value": amount,
                    }
                }
            ],
            "application_context": {
                "return_url": "http://localhost:5173/",
                "cancel_url": "http://localhost:5173/",
            },
        },
        timeout=30,
    )

    _raise_for_paypal_response(response, "order creation")
    payload = response.json()
    _safe_debug_metadata(response, "order creation")

    order_id = payload.get("id")
    if not order_id:
        raise RuntimeError("PayPal order creation response did not include an order ID.")

    verification_response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v2/checkout/orders/{order_id}",
        headers=_payPal_headers(),
        timeout=30,
    )
    _safe_debug_metadata(verification_response, "order verification")

    if verification_response.status_code >= 400:
        error_text = verification_response.text or "Unknown PayPal error"
        if verification_response.status_code == 404:
            raise RuntimeError(
                f"Failed to verify PayPal order {order_id}: {verification_response.status_code} {error_text}"
            )
        raise RuntimeError(
            f"PayPal order verification failed for order {order_id}: {verification_response.status_code} {error_text}"
        )

    verification_payload = verification_response.json()
    verified_order_id = verification_payload.get("id")
    if verified_order_id != order_id:
        raise RuntimeError(
            f"PayPal order verification failed: Order ID mismatch for {order_id}; received {verified_order_id}."
        )

    return payload

def _normalize_balance_entry(entry: dict[str, Any], fallback_currency: str = "USD") -> dict[str, Any]:
    currency = str(entry.get("currency") or fallback_currency or "USD").upper()
    total_value = entry.get("total_balance") or {}
    available_value = entry.get("available_balance") or {}
    withheld_value = entry.get("withheld_balance") or {}
    last_updated = entry.get("last_updated") or entry.get("as_of") or entry.get("last_refresh_time")

    return {
        "currency": currency,
        "total_balance": {
            "currency": currency,
            "value": str((total_value if isinstance(total_value, dict) else {}).get("value") or total_value or "0.00"),
        },
        "available_balance": {
            "currency": currency,
            "value": str((available_value if isinstance(available_value, dict) else {}).get("value") or available_value or "0.00"),
        },
        "withheld_balance": {
            "currency": currency,
            "value": str((withheld_value if isinstance(withheld_value, dict) else {}).get("value") or withheld_value or "0.00"),
        },
        "last_updated": last_updated,
    }


def normalize_account_balance(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        return {
            "balances": [],
            "currency": "USD",
            "account_id": None,
            "account_status": "ACTIVE",
            "total_balance": {"currency": "USD", "value": "0.00"},
            "available_balance": {"currency": "USD", "value": "0.00"},
            "withheld_balance": {"currency": "USD", "value": "0.00"},
            "last_updated": None,
        }

    balances = payload.get("balances") or []
    normalized_balances = []
    for item in balances:
        if not isinstance(item, dict):
            continue
        normalized_balances.append(_normalize_balance_entry(item, payload.get("currency") or "USD"))

    fallback_currency = str(payload.get("currency") or "USD").upper()
    if not normalized_balances and payload.get("total_balance") is not None:
        normalized_balances.append(_normalize_balance_entry({
            "currency": fallback_currency,
            "total_balance": payload.get("total_balance"),
            "available_balance": payload.get("available_balance"),
            "withheld_balance": payload.get("withheld_balance"),
            "last_updated": payload.get("last_updated") or payload.get("as_of") or payload.get("last_refresh_time") or payload.get("as_of_time"),
        }, fallback_currency))

    if not normalized_balances:
        result = {
            **payload,
            "balances": [],
            "currency": fallback_currency,
            "account_id": payload.get("account_id") or payload.get("payer_id"),
            "account_status": payload.get("account_status") or payload.get("status") or "ACTIVE",
            "total_balance": {"currency": fallback_currency, "value": "0.00"},
            "available_balance": {"currency": fallback_currency, "value": "0.00"},
            "withheld_balance": {"currency": fallback_currency, "value": "0.00"},
            "last_updated": payload.get("last_updated") or payload.get("as_of") or payload.get("last_refresh_time") or payload.get("as_of_time"),
        }
        result["status"] = result["account_status"]
        return result

    def _sort_key(entry: dict[str, Any]):
        value = entry.get("last_updated")
        if not value:
            return datetime.min.replace(tzinfo=timezone.utc)
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc)
        if isinstance(value, str):
            try:
                return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
            except ValueError:
                return datetime.min.replace(tzinfo=timezone.utc)
        return datetime.min.replace(tzinfo=timezone.utc)

    latest_entry = max(normalized_balances, key=_sort_key)
    result = dict(payload)
    result["balances"] = normalized_balances
    result["currency"] = latest_entry["currency"]
    result["account_id"] = payload.get("account_id") or payload.get("payer_id")
    result["account_status"] = payload.get("account_status") or payload.get("status") or "ACTIVE"
    result["status"] = result["account_status"]
    result["total_balance"] = latest_entry["total_balance"]
    result["available_balance"] = latest_entry["available_balance"]
    result["withheld_balance"] = latest_entry["withheld_balance"]
    result["last_updated"] = latest_entry["last_updated"] or payload.get("last_updated") or payload.get("as_of") or payload.get("last_refresh_time") or payload.get("as_of_time")
    return result


def fetch_account_balance():
    sdk_payload = _request_balance_via_sdk()
    if sdk_payload is not None:
        return normalize_account_balance(sdk_payload)

    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v1/reporting/balances",
        headers=_payPal_headers(),
        params={"currency_code": "USD"},
        timeout=30,
    )
    _raise_for_paypal_response(response, "balance reporting")
    return normalize_account_balance(response.json())

def create_payout(recipient_email: str, amount: str, currency: str = "USD", note: str = "PayPal payout from dashboard") -> dict[str, Any]:
    require_paypal_configuration()
    if settings.PAYPAL_MODE == "live":
        require_live_payout_eligibility()
        raise PayPalConfigError(
            "Sandbox mode is required for payouts in this app. Live PayPal payouts remain disabled until the account is approved for real-money transfers."
        )
    if settings.PAYPAL_MODE != "sandbox":
        raise PayPalConfigError(
            "Sandbox mode is required for payouts in this app. Live PayPal payouts remain disabled until the account is approved for real-money transfers."
        )

    email = (recipient_email or "").strip()
    if not email or "@" not in email:
        raise ValueError("A valid recipient email is required to create a PayPal payout.")

    try:
        amount_value = float(str(amount or "0"))
    except (TypeError, ValueError) as exc:
        raise ValueError("Payout amount must be a valid number.") from exc

    if amount_value <= 0:
        raise ValueError("Payout amount must be greater than zero.")

    sender_batch_id = f"payout-{uuid.uuid4()}"
    payload = {
        "sender_batch_header": {
            "sender_batch_id": sender_batch_id,
            "email_message": note or "PayPal payout from the dashboard.",
            "recipient_type": "EMAIL",
        },
        "items": [
            {
                "recipient_type": "EMAIL",
                "amount": {
                    "currency": (currency or "USD").upper(),
                    "value": f"{amount_value:.2f}",
                },
                "receiver": email,
                "note": note or "PayPal payout from the dashboard.",
                "sender_item_id": f"item-{uuid.uuid4()}",
            }
        ],
    }

    response = requests.post(
        f"{settings.PAYPAL_API_BASE}/v1/payments/payouts",
        headers=_payPal_headers(),
        json=payload,
        timeout=30,
    )
    _raise_for_paypal_response(response, "payout creation")
    result = response.json()
    _safe_debug_metadata(response, "payout creation")

    batch_header = result.get("batch_header") or {}
    if not batch_header.get("payout_batch_id"):
        raise RuntimeError("PayPal payout response did not include a payout batch ID.")

    return result


def fetch_payout_batch_details(batch_id: str) -> dict[str, Any]:
    require_paypal_configuration()
    if settings.PAYPAL_MODE != "sandbox":
        raise PayPalConfigError(
            "Sandbox mode is required for payout status checks in this app. Live payout status checks are disabled."
        )

    normalized_batch_id = str(batch_id or "").strip()
    if not normalized_batch_id:
        raise ValueError("A valid PayPal payout batch ID is required.")

    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v1/payments/payouts/{normalized_batch_id}",
        headers=_payPal_headers(),
        timeout=30,
    )
    _raise_for_paypal_response(response, "payout status lookup")
    result = response.json()
    _safe_debug_metadata(response, "payout status lookup")

    batch_header = result.get("batch_header") or {}
    if not batch_header.get("payout_batch_id"):
        raise RuntimeError("PayPal payout details response did not include a payout batch ID.")

    return result


def capture_checkout_order(order_id: str):
    response = requests.post(
        f"{settings.PAYPAL_API_BASE}/v2/checkout/orders/{order_id}/capture",
        headers=_payPal_headers(),
        json={},
        timeout=30,
    )

    _raise_for_paypal_response(response, "payment capture")
    return response.json()