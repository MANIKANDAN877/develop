from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import datetime, timedelta
from pathlib import Path

import requests

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

# Make sure the project package resolves from the backend directory itself.
sys.path.insert(0, str(BASE_DIR))

from app.config import settings


def print_section(title: str):
    print(f"\n=== {title} ===")


def safe_json(data):
    if isinstance(data, (dict, list)):
        return json.dumps(data, default=str)[:500]
    return str(data)[:500]


def format_error(resp, label):
    try:
        body = resp.json()
    except Exception:
        body = resp.text
    print(f"{label}_STATUS", resp.status_code)
    if isinstance(body, dict):
        msg = body.get("error") or body.get("message") or body.get("details") or safe_json(body)
    else:
        msg = str(body)[:500]
    print(f"{label}_MESSAGE", msg)


# Start backend in a subprocess (if not already running)
proc = None
try:
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=str(BASE_DIR),
        env={**os.environ, "PYTHONPATH": str(BASE_DIR)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    time.sleep(8)
except Exception as exc:
    print("SERVER_START_ERROR", repr(exc))

print_section("Python runtime and config")
print("PYTHON", sys.executable)
print("PAYPAL_MODE", settings.PAYPAL_MODE)
print("PAYPAL_API_BASE", settings.PAYPAL_API_BASE)
print("HAS_CLIENT_ID", bool(settings.PAYPAL_CLIENT_ID))
print("HAS_CLIENT_SECRET", bool(settings.PAYPAL_CLIENT_SECRET))
print("DB_URL", settings.DATABASE_URL)

print_section("OAuth")
auth_resp = requests.post(
    f"{settings.PAYPAL_API_BASE}/v1/oauth2/token",
    auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET),
    data={"grant_type": "client_credentials"},
    timeout=30,
)
print("OAUTH_STATUS", auth_resp.status_code)
if auth_resp.status_code != 200:
    format_error(auth_resp, "OAUTH")
    raise SystemExit(1)
body = auth_resp.json()
print("OAUTH_KEYS", sorted(body.keys()))
print("HAS_ACCESS_TOKEN", "access_token" in body)
print("TOKEN_TYPE", body.get("token_type"))
print("EXPIRES_IN", body.get("expires_in"))

access_token = body["access_token"]
headers = {"Authorization": f"Bearer {access_token}", "Content-Type": "application/json"}

print_section("Balance reporting")
end = datetime.utcnow()
start = end - timedelta(days=30)
start_iso = start.strftime("%Y-%m-%dT%H:%M:%SZ")
end_iso = end.strftime("%Y-%m-%dT%H:%M:%SZ")

balance_resp = requests.get(
    f"{settings.PAYPAL_API_BASE}/v1/reporting/balances",
    headers=headers,
    params={"currency_code": "USD"},
    timeout=30,
)
print("BALANCE_STATUS", balance_resp.status_code)
if balance_resp.status_code != 200:
    format_error(balance_resp, "BALANCE")
else:
    balance_json = balance_resp.json()
    print("BALANCE_KEYS", sorted(balance_json.keys()))
    balances = balance_json.get("balances", [])
    print("BALANCE_COUNT", len(balances))
    if balances:
        first = balances[0]
        print("FIRST_BALANCE", {
            "currency": first.get("currency"),
            "total_balance": first.get("total_balance"),
            "available_balance": first.get("available_balance"),
            "pending_balance": first.get("pending_balance"),
        })

print_section("Transaction search")
search_resp = requests.get(
    f"{settings.PAYPAL_API_BASE}/v1/reporting/transactions",
    headers=headers,
    params={"start_date": start_iso, "end_date": end_iso, "page_size": 100},
    timeout=30,
)
print("SEARCH_STATUS", search_resp.status_code)
if search_resp.status_code != 200:
    format_error(search_resp, "TRANSACTION_SEARCH")
    # If permission is missing, report the required scope clearly without manufacturing data.
    if search_resp.status_code in (401, 403):
        print("SCOPE_HINT", "Required PayPal scope may include reporting.transactions.read and reporting.balances.read.")
else:
    search_json = search_resp.json()
    print("SEARCH_KEYS", sorted(search_json.keys()))
    details = search_json.get("transaction_details", [])
    print("SEARCH_RESULT_COUNT", len(details))
    if details:
        first = details[0]
        first_info = first.get("transaction_info", {})
        print("FIRST_TRANSACTION_ID", first_info.get("transaction_id"))
        print("FIRST_TRANSACTION_TYPE", first_info.get("transaction_type"))
        print("FIRST_TRANSACTION_STATUS", first_info.get("transaction_status"))
        print("FIRST_PAYER_EMAIL", (first.get("payer_info", {}) or {}).get("email"))
        print("FIRST_AMOUNT", (first_info.get("transaction_amount") or {}).get("value"))
        print("FIRST_CURRENCY", (first_info.get("transaction_amount") or {}).get("currency"))
        print("FIRST_SOURCE", first.get("source_reference") or "/v1/reporting/transactions")

print_section("Backend import")
backend_import = requests.post(
    "http://127.0.0.1:8000/api/paypal/import",
    params={"start_date": start_iso, "end_date": end_iso},
    timeout=120,
)
print("IMPORT_STATUS", backend_import.status_code)
print("IMPORT_BODY", backend_import.text[:1000])
import_payload = backend_import.json() if backend_import.headers.get("content-type", "").startswith("application/json") else {}
if import_payload.get("status") == "ok":
    print("IMPORTED_COUNT", import_payload.get("imported_count"))
    print("DUPLICATES_SKIPPED", import_payload.get("duplicates_skipped"))
    print("ALERT_COUNT", len(import_payload.get("alerts", [])))

print_section("Duplicate prevention")
duplicate_import = requests.post(
    "http://127.0.0.1:8000/api/paypal/import",
    params={"start_date": start_iso, "end_date": end_iso},
    timeout=120,
)
print("SECOND_IMPORT_STATUS", duplicate_import.status_code)
second_payload = duplicate_import.json() if duplicate_import.headers.get("content-type", "").startswith("application/json") else {}
print("SECOND_IMPORT_BODY", duplicate_import.text[:1000])
if second_payload:
    print("SECOND_IMPORTED_COUNT", second_payload.get("imported_count"))
    print("SECOND_DUPLICATES_SKIPPED", second_payload.get("duplicates_skipped"))

print_section("Transactions list and lookup")
list_resp = requests.get("http://127.0.0.1:8000/api/paypal/transactions", timeout=60)
print("LIST_STATUS", list_resp.status_code)
list_json = list_resp.json() if list_resp.headers.get("content-type", "").startswith("application/json") else {}
print("LIST_COUNT", list_json.get("count"))
print("LIST_SAMPLE", safe_json(list_json.get("results", [])[:1]))

lookup_tx_id = None
if list_json.get("results"):
    lookup_tx_id = list_json["results"][0].get("paypal_transaction_id")
    print("LOOKUP_TX_ID", lookup_tx_id)
    lookup_resp = requests.get(
        "http://127.0.0.1:8000/api/paypal/transactions/search",
        params={"transaction_id": lookup_tx_id},
        timeout=60,
    )
    print("LOOKUP_STATUS", lookup_resp.status_code)
    print("LOOKUP_BODY", lookup_resp.text[:1000])

print_section("Alerts")
alerts_resp = requests.get("http://127.0.0.1:8000/api/paypal/alerts", timeout=60)
print("ALERTS_STATUS", alerts_resp.status_code)
alerts_json = alerts_resp.json() if alerts_resp.headers.get("content-type", "").startswith("application/json") else {}
print("ALERTS_COUNT", alerts_json.get("count"))
print("ALERTS_SAMPLE", safe_json(alerts_json.get("results", [])[:3]))

print_section("Dashboard data source")
print("DASHBOARD_DATA_SOURCE", "GET /api/paypal/transactions")
print("DASHBOARD_COUNT_FROM_API", list_json.get("count"))

if proc is not None:
    try:
        proc.terminate()
        proc.wait(timeout=15)
        print("SERVER_EXIT_CODE", proc.returncode)
    except Exception as exc:
        print("SERVER_STOP_ERROR", repr(exc))
