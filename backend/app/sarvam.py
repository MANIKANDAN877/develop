from __future__ import annotations

import json
import re
import threading
import time
from typing import Any

import requests

from .config import settings

SARVAM_ENDPOINT = "https://api.sarvam.ai/v1/chat/completions"
SARVAM_MODEL = "sarvam-105b"
_REQUEST_HISTORY: list[float] = []
_REQUEST_HISTORY_LOCK = threading.Lock()


def _rate_limit_allowed(limit_per_minute: int = 5) -> bool:
    now = time.monotonic()
    with _REQUEST_HISTORY_LOCK:
        window_start = now - 60
        live_times = [stamp for stamp in _REQUEST_HISTORY if stamp >= window_start]
        if len(live_times) >= limit_per_minute:
            _REQUEST_HISTORY[:] = live_times
            return False
        live_times.append(now)
        _REQUEST_HISTORY[:] = live_times
        return True


def _sanitize_evidence(evidence: Any) -> Any:
    if not isinstance(evidence, dict):
        return evidence

    blocked_keys = {
        "payer_email",
        "payer_name",
        "email",
        "password",
        "password_hash",
        "api_key",
        "secret",
        "token",
        "access_token",
        "client_secret",
    }
    cleaned: dict[str, Any] = {}
    for key, value in evidence.items():
        if key.lower() in blocked_keys:
            continue
        cleaned[key] = value
    return cleaned


def _sanitize_transaction(transaction: dict[str, Any] | None) -> dict[str, Any]:
    if not transaction:
        return {}

    sanitized = {
        "paypal_transaction_id": transaction.get("paypal_transaction_id"),
        "amount": transaction.get("amount"),
        "currency": transaction.get("currency"),
        "transaction_status": transaction.get("transaction_status"),
        "payment_status": transaction.get("payment_status"),
        "environment": transaction.get("environment"),
        "source_reference": transaction.get("source_reference"),
        "created_at": transaction.get("created_at"),
    }
    return {key: value for key, value in sanitized.items() if value is not None}


def _parse_ai_json(content: str) -> dict[str, Any] | None:
    try:
        parsed = json.loads(content)
        if isinstance(parsed, dict):
            return parsed
    except json.JSONDecodeError:
        pass

    cleaned = content.strip()
    if cleaned.startswith("```"):
        cleaned = cleaned.strip("` ")
        if cleaned.lower().startswith("json"):
            cleaned = cleaned[4:].lstrip()
    match = re.search(r"\{.*\}", cleaned, re.DOTALL)
    if match:
        try:
            parsed = json.loads(match.group(0))
            if isinstance(parsed, dict):
                return parsed
        except json.JSONDecodeError:
            return None
    return None


def _extract_provider_error(response: Any) -> str:
    try:
        payload = response.json()
    except (AttributeError, ValueError, TypeError):
        text = getattr(response, "text", "")
        return str(text)[:500].strip() or "Unknown API error"

    if isinstance(payload, dict):
        for key in ("error", "message", "detail", "code"):
            value = payload.get(key)
            if isinstance(value, dict):
                nested_message = value.get("message") or value.get("error") or value.get("detail")
                if nested_message:
                    return str(nested_message)[:500]
                return str(value)[:500]
            if value is not None:
                return str(value)[:500]
        return str(payload)[:500]
    return str(payload)[:500]


def _unavailable_response(provider_status: int | None = None, provider_error: str | None = None) -> dict[str, Any]:
    response = {
        "status": "unavailable",
        "explanation": "AI explanation unavailable.",
        "risk_factors": [],
        "recommended_action": "Manual review by a human analyst; do not auto-approve or reject this payment.",
        "ai_model": SARVAM_MODEL,
    }
    if provider_status is not None:
        response["provider_status"] = provider_status
    if provider_error:
        response["provider_error"] = provider_error
    return response


def generate_ai_explanation(alert: dict[str, Any] | None, transaction: dict[str, Any] | None) -> dict[str, Any]:
    if not settings.SARVAM_API_KEY:
        return _unavailable_response()

    if not _rate_limit_allowed():
        return {
            **_unavailable_response(),
            "status": "rate_limited",
            "explanation": "AI explanation unavailable because the service rate limit was reached.",
        }

    sanitized_transaction = _sanitize_transaction(transaction)
    sanitized_alert = {
        "alert_type": (alert or {}).get("alert_type"),
        "severity": (alert or {}).get("severity"),
        "risk_score": (alert or {}).get("risk_score"),
        "message": (alert or {}).get("message"),
        "evidence": _sanitize_evidence((alert or {}).get("evidence")),
        "status": (alert or {}).get("status"),
    }

    prompt = {
        "transaction": sanitized_transaction,
        "alert": {key: value for key, value in sanitized_alert.items() if value is not None},
        "instructions": [
            "Explain why this transaction was flagged.",
            "List the specific risk factors detected.",
            "Describe what the reviewer should investigate.",
            "Provide a concise summary.",
            "Never approve, reject, capture, or refund the payment.",
            "Do not reference or include payer email, passwords, API keys, or other unnecessary personal identifiers.",
        ],
    }

    try:
        response = requests.post(
            f"{settings.SARVAM_API_BASE}/v1/chat/completions",
            headers={
                "Content-Type": "application/json",
                "api-subscription-key": settings.SARVAM_API_KEY,
            },
            json={
                "model": settings.SARVAM_MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": (
                            "You are a fraud review assistant. Use only the supplied transaction metadata and rule-based risk signals. "
                            "Return strict JSON with keys explanation, risk_factors, recommended_action, ai_model. "
                            "Do not approve, reject, capture, refund, or override payment logic."
                        ),
                    },
                    {"role": "user", "content": json.dumps(prompt, separators=(",", ":"))},
                ],
                "temperature": 0.2,
                "top_p": 0.9,
                "max_tokens": 300,
            },
            timeout=15,
        )
        status_code = getattr(response, "status_code", None)
        if status_code is not None and status_code >= 400:
            return _unavailable_response(
                provider_status=status_code,
                provider_error=_extract_provider_error(response),
            )

        if hasattr(response, "raise_for_status"):
            response.raise_for_status()
        payload = response.json()
        content = payload.get("choices", [{}])[0].get("message", {}).get("content", "")
        parsed = _parse_ai_json(content)
        if not parsed:
            return _unavailable_response()

        result = {
            "status": "ok",
            "explanation": str(parsed.get("explanation") or "AI explanation unavailable."),
            "risk_factors": parsed.get("risk_factors") or [],
            "recommended_action": str(parsed.get("recommended_action") or "Manual review by a human analyst."),
            "ai_model": str(parsed.get("ai_model") or settings.SARVAM_MODEL),
        }
        return result
    except (AttributeError, requests.RequestException, RuntimeError, ValueError, TypeError, KeyError):
        return _unavailable_response()
