from collections import defaultdict
from datetime import datetime
from statistics import median


def _to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_datetime(value):
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


def generate_fraud_alerts(records):
    alerts = []
    if not records:
        return alerts

    amounts = []
    failed_by_payer = defaultdict(int)
    frequency_by_payer = defaultdict(list)
    duplicate_bucket = defaultdict(list)

    for record in records:
        value = _to_float(record.get("amount"))
        if value is not None:
            amounts.append(value)

        payer_email = record.get("payer_email") or record.get("payer_name")
        if payer_email:
            failed_status = (record.get("transaction_status") or "").lower()
            if failed_status in {"failed", "denied", "expired", "canceled"}:
                failed_by_payer[payer_email] += 1

            timestamp = _as_datetime(record.get("created_at") or record.get("captured_at"))
            if timestamp:
                frequency_by_payer[payer_email].append(timestamp)

        key = (record.get("payer_email"), record.get("currency"), record.get("amount"))
        duplicate_bucket[key].append(record)

    for key, bucket in duplicate_bucket.items():
        if len(bucket) > 1:
            for record in bucket:
                alerts.append(
                    {
                        "paypal_transaction_id": record.get("paypal_transaction_id"),
                        "alert_type": "duplicate_payment",
                        "severity": "medium",
                        "risk_score": 66,
                        "message": "Review required: repeated payment with the same payer and amount detected.",
                        "evidence": {"payer_email": record.get("payer_email"), "amount": record.get("amount")},
                        "status": "review",
                    }
                )

    if amounts:
        median_amount = median(amounts)
        if len(amounts) < 2:
            threshold = 1000.0
        else:
            threshold = max(median_amount * 5, 1000.0)
        for record in records:
            value = _to_float(record.get("amount"))
            if value is not None and value > threshold:
                alerts.append(
                    {
                        "paypal_transaction_id": record.get("paypal_transaction_id"),
                        "alert_type": "unusual_amount",
                        "severity": "high",
                        "risk_score": 92,
                        "message": "Review required: transaction amount is materially higher than the median in the retrieved dataset.",
                        "evidence": {"amount": record.get("amount"), "median_amount": round(median_amount, 2)},
                        "status": "review",
                    }
                )

    for payer_email, count in failed_by_payer.items():
        if count >= 2:
            for record in records:
                if (record.get("payer_email") or record.get("payer_name")) == payer_email:
                    alerts.append(
                        {
                            "paypal_transaction_id": record.get("paypal_transaction_id"),
                            "alert_type": "repeated_failed_payment",
                            "severity": "high",
                            "risk_score": 88,
                            "message": "Review required: repeated failed payments have been observed for the same payer.",
                            "evidence": {"payer_email": payer_email, "failed_count": count},
                            "status": "review",
                        }
                    )

    for payer_email, timestamps in frequency_by_payer.items():
        if len(timestamps) >= 4:
            sorted_times = sorted(timestamps)
            for idx in range(len(sorted_times) - 3):
                window = sorted_times[idx + 3] - sorted_times[idx]
                if window.total_seconds() <= 1800:
                    for record in records:
                        if (record.get("payer_email") or record.get("payer_name")) == payer_email:
                            alerts.append(
                                {
                                    "paypal_transaction_id": record.get("paypal_transaction_id"),
                                    "alert_type": "unusual_transaction_frequency",
                                    "severity": "medium",
                                    "risk_score": 72,
                                    "message": "Review required: unusually rapid payment frequency indicates a possible suspicious pattern.",
                                    "evidence": {"payer_email": payer_email, "window_seconds": int(window.total_seconds())},
                                    "status": "review",
                                }
                            )
                    break

    for record in records:
        payer_email = record.get("payer_email") or record.get("payer_name")
        status = (record.get("transaction_status") or "").lower()
        amount_value = _to_float(record.get("amount"))
        if payer_email and status in {"failed", "denied"} and amount_value and amount_value > 500:
            alerts.append(
                {
                    "paypal_transaction_id": record.get("paypal_transaction_id"),
                    "alert_type": "suspicious_payment_pattern",
                    "severity": "medium",
                    "risk_score": 80,
                    "message": "Review required: a high-value failed or denied payment can indicate a suspicious payment pattern.",
                    "evidence": {"payer_email": payer_email, "amount": record.get("amount")},
                    "status": "review",
                }
            )

    deduped = []
    seen = set()
    for alert in alerts:
        key = (
            alert.get("paypal_transaction_id"),
            alert.get("alert_type"),
            alert.get("message"),
        )
        if key not in seen:
            seen.add(key)
            deduped.append(alert)

    return deduped
