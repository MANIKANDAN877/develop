import re
import sys

import requests

from app.config import settings
from app.paypal import PayPalConfigError, get_access_token


def main() -> None:
    try:
        token = get_access_token()
        if not token or len(token) < 10:
            raise PayPalConfigError("No access token received.")

        response = requests.post(
            f"{settings.PAYPAL_API_BASE}/v1/oauth2/token",
            auth=(settings.PAYPAL_CLIENT_ID, settings.PAYPAL_CLIENT_SECRET),
            data={"grant_type": "client_credentials"},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()

        token_type = str(payload.get("token_type", "")).strip()
        expires_in = int(payload.get("expires_in", 0) or 0)

        if token_type != "Bearer" or expires_in <= 0:
            raise PayPalConfigError("Token validation failed.")

        print("Authentication: PASS")
        print("PayPal API connection: PASS")
        print(f"Token expiry: {expires_in} seconds")
        print("Error details: None")
        return

    except Exception as exc:
        msg = str(exc)
        msg = re.sub(r"(?i)(PAYPAL_CLIENT_SECRET\s*[:=]\s*)[^\s,]+", r"\1[REDACTED]", msg)
        msg = re.sub(r"(?i)(access_token\s*[:=]\s*)[^\s,]+", r"\1[REDACTED]", msg)
        print("Authentication: FAIL")
        print("PayPal API connection: FAIL")
        print("Token expiry: 0 seconds")
        print(f"Error details: {type(exc).__name__}: {msg[:250]}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
