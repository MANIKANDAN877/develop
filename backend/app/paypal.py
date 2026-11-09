from __future__ import annotations

from datetime import datetime
from typing import Any

import requests

from .config import settings


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


def get_access_token() -> str:
    require_paypal_configuration()
    payload = requests.post(
        f"{settings.PAYPAL_API_BASE}/v1/oauth2/token",
        auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET),
        data={"grant_type": "client_credentials"},
        timeout=30,
    )
    if payload.status_code != 200:
        raise PayPalConfigError(
            f"PayPal OAuth failed with status {payload.status_code}: {payload.text}"
        )
    access_token = payload.json().get("access_token")
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
    if response.status_code == 403:
        error_text = response.text or "The PayPal Reporting API permission is not authorized."
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


def fetch_account_balance():
    response = requests.get(
        f"{settings.PAYPAL_API_BASE}/v1/reporting/balances",
        headers=_payPal_headers(),
        params={"currency_code": "USD"},
        timeout=30,
    )
    _raise_for_paypal_response(response, "balance reporting")
    return response.json()
