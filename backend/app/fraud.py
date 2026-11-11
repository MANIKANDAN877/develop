from collections import defaultdict
from datetime import datetime
from pathlib import Path
from statistics import median

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
import joblib


MODEL_DIR = Path(__file__).resolve().parent.parent / "artifacts"
MODEL_PATH = MODEL_DIR / "fraud_model.joblib"
ML_FEATURE_NAMES = [
    "amount",
    "transaction_frequency",
    "unusual_transaction_time",
    "repeated_recipient",
    "transaction_velocity",
    "unusual_spending_pattern",
]


def _to_float(value, default=None):
    try:
        numeric = float(value)
        return numeric if numeric == numeric else default
    except (TypeError, ValueError):
        return default


def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


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


def classify_risk_level(score):
    numeric_score = _to_float(score, 0.0) or 0.0
    if numeric_score < 30:
        return "LOW RISK"
    if numeric_score < 70:
        return "MEDIUM RISK"
    return "HIGH RISK"


def build_training_dataset():
    dataset = []

    low_risk_base = [
        (30, 1, 0, 0, 0.12, 0),
        (42, 1, 0, 0, 0.14, 0),
        (55, 2, 0, 0, 0.17, 0),
        (65, 1, 0, 0, 0.15, 0),
        (74, 1, 0, 0, 0.18, 0),
        (85, 2, 0, 0, 0.21, 0),
        (110, 1, 0, 0, 0.22, 0),
        (130, 2, 0, 0, 0.24, 0),
        (140, 1, 0, 0, 0.23, 0),
        (160, 2, 0, 0, 0.26, 0),
        (180, 2, 0, 0, 0.28, 0),
        (200, 2, 0, 0, 0.29, 0),
        (220, 3, 0, 0, 0.31, 0),
        (250, 2, 0, 0, 0.33, 0),
        (290, 2, 0, 0, 0.35, 0),
        (315, 1, 0, 0, 0.37, 0),
        (340, 2, 0, 0, 0.38, 0),
        (380, 1, 0, 0, 0.41, 0),
        (420, 2, 0, 0, 0.43, 0),
        (455, 2, 0, 0, 0.45, 0),
    ]
    for amount, frequency, unusual_time, repeated_recipient, velocity, unusual_spending in low_risk_base:
        dataset.append(
            {
                "amount": amount,
                "transaction_frequency": frequency,
                "unusual_transaction_time": unusual_time,
                "repeated_recipient": repeated_recipient,
                "transaction_velocity": velocity,
                "unusual_spending_pattern": unusual_spending,
                "label": 0,
                "synthetic": True,
            }
        )

    medium_risk_base = [
        (610, 3, 1, 0, 0.52, 0),
        (680, 2, 1, 0, 0.58, 1),
        (740, 4, 1, 1, 0.62, 1),
        (820, 4, 1, 1, 0.61, 1),
        (920, 3, 1, 1, 0.68, 1),
        (980, 5, 1, 1, 0.72, 1),
        (1050, 4, 1, 1, 0.76, 1),
        (1125, 5, 1, 1, 0.78, 1),
        (1200, 5, 1, 1, 0.82, 1),
        (1350, 4, 1, 1, 0.84, 1),
    ]
    for amount, frequency, unusual_time, repeated_recipient, velocity, unusual_spending in medium_risk_base:
        dataset.append(
            {
                "amount": amount,
                "transaction_frequency": frequency,
                "unusual_transaction_time": unusual_time,
                "repeated_recipient": repeated_recipient,
                "transaction_velocity": velocity,
                "unusual_spending_pattern": unusual_spending,
                "label": 1,
                "synthetic": True,
            }
        )

    high_risk_base = [
        (1450, 6, 1, 1, 0.9, 1),
        (1600, 6, 1, 1, 0.92, 1),
        (1750, 7, 1, 1, 0.95, 1),
        (1900, 7, 1, 1, 0.96, 1),
        (2150, 8, 1, 1, 0.98, 1),
        (2400, 8, 1, 1, 1.0, 1),
        (2800, 9, 1, 1, 1.0, 1),
        (3200, 9, 1, 1, 1.0, 1),
        (3600, 10, 1, 1, 1.0, 1),
        (4200, 10, 1, 1, 1.0, 1),
    ]
    for amount, frequency, unusual_time, repeated_recipient, velocity, unusual_spending in high_risk_base:
        dataset.append(
            {
                "amount": amount,
                "transaction_frequency": frequency,
                "unusual_transaction_time": unusual_time,
                "repeated_recipient": repeated_recipient,
                "transaction_velocity": velocity,
                "unusual_spending_pattern": unusual_spending,
                "label": 1,
                "synthetic": True,
            }
        )

    return dataset


def _load_model_payload():
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    if MODEL_PATH.exists():
        try:
            payload = joblib.load(MODEL_PATH)
            if isinstance(payload, dict) and "model" in payload and "feature_names" in payload:
                return payload
        except Exception:
            pass

    model = create_ml_fraud_model()
    return model


def _prepare_feature_vector(record):
    amount = _to_float(record.get("amount"), 0.0) or 0.0
    transaction_frequency = _to_float(record.get("transaction_frequency"), 0.0) or 0.0
    unusual_transaction_time = _to_float(record.get("unusual_transaction_time"), 0.0) or 0.0
    repeated_recipient = _to_float(record.get("repeated_recipient"), 0.0) or 0.0
    transaction_velocity = _to_float(record.get("transaction_velocity"), 0.0) or 0.0
    unusual_spending_pattern = _to_float(record.get("unusual_spending_pattern"), 0.0) or 0.0

    return {
        "amount": amount,
        "transaction_frequency": transaction_frequency,
        "unusual_transaction_time": unusual_transaction_time,
        "repeated_recipient": repeated_recipient,
        "transaction_velocity": transaction_velocity,
        "unusual_spending_pattern": unusual_spending_pattern,
    }


def create_ml_fraud_model():
    dataset = build_training_dataset()
    feature_names = ML_FEATURE_NAMES
    labels = [int(row["label"]) for row in dataset]
    feature_matrix = [[row[name] for name in feature_names] for row in dataset]

    model = RandomForestClassifier(
        n_estimators=200,
        random_state=42,
        class_weight="balanced",
        max_depth=None,
    )
    model.fit(feature_matrix, labels)

    predictions = model.predict(feature_matrix)
    metrics = {
        "accuracy": round(float(accuracy_score(labels, predictions)), 4),
        "precision": round(float(precision_score(labels, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(labels, predictions, zero_division=0)), 4),
        "f1_score": round(float(f1_score(labels, predictions, zero_division=0)), 4),
        "confusion_matrix": [[int(value) for value in row] for row in confusion_matrix(labels, predictions).tolist()],
    }

    payload = {
        "model": model,
        "feature_names": feature_names,
        "training_data_source": "synthetic",
        "model_type": "random_forest",
        "model_version": "synthetic-rf-v1",
        "risk_thresholds": {"low": 30, "medium": 70},
        "metrics": metrics,
        "notes": "The model is trained only on synthetic data. Real PayPal Sandbox transactions are scored for review and never used as training input.",
    }
    MODEL_DIR.mkdir(parents=True, exist_ok=True)
    joblib.dump(payload, MODEL_PATH)
    return payload


def score_transaction(record):
    if not record:
        return {
            "transaction_id": None,
            "fraud_probability": 0.0,
            "risk_level": "LOW RISK",
            "risk_thresholds": {"low": 30, "medium": 70},
            "training_data_source": "synthetic",
            "feature_values": {},
            "model_type": "random_forest",
            "note": "No transaction payload was supplied.",
        }

    payload = _load_model_payload()
    feature_values = _prepare_feature_vector(record)
    feature_vector = [feature_values[name] for name in payload["feature_names"]]
    prediction_probability = payload["model"].predict_proba([feature_vector])[0][1]
    fraud_probability = round(max(0.0, min(100.0, float(prediction_probability) * 100.0)), 2)
    return {
        "transaction_id": record.get("paypal_transaction_id") or record.get("transaction_id") or "unknown",
        "fraud_probability": fraud_probability,
        "risk_level": classify_risk_level(fraud_probability),
        "risk_thresholds": payload.get("risk_thresholds", {"low": 30, "medium": 70}),
        "training_data_source": payload.get("training_data_source", "synthetic"),
        "model_type": payload.get("model_type", "random_forest"),
        "model_version": payload.get("model_version", "synthetic-rf-v1"),
        "feature_values": feature_values,
        "note": "Machine learning score is synthetic-model based only; real PayPal Sandbox transactions remain for review and monitoring, not model training.",
    }


def summarize_ml_scores(records):
    scored_records = [score_transaction(record) for record in records]
    distribution = {"LOW RISK": 0, "MEDIUM RISK": 0, "HIGH RISK": 0}
    for item in scored_records:
        distribution[item["risk_level"]] = distribution.get(item["risk_level"], 0) + 1
    average_score = round(
        sum(item["fraud_probability"] for item in scored_records) / len(scored_records),
        2,
    ) if scored_records else 0.0
    return {
        "average_risk_score": average_score,
        "risk_distribution": distribution,
        "scored_transactions": scored_records,
        "training_data_source": "synthetic",
        "model_type": "random_forest",
    }


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
