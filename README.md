# PayPal Fraud Detection & Payment Finder

This project is a React + Vite frontend and FastAPI backend for retrieving PayPal Sandbox transaction data, persisting authenticated API results in PostgreSQL, and generating review alerts for suspicious payment behavior.

## Project structure

- frontend/: Vite React dashboard
- backend/: FastAPI application and tests
- docker-compose.yml: PostgreSQL service
- .env.example: required environment settings

The backend uses the Python 3.13-compatible psycopg driver in place of the older psycopg2 binary, which does not build successfully on this runtime without the full C++ toolchain.

Production use is PostgreSQL-backed. In this local environment, the app falls back to a local SQLite database when no PostgreSQL URL is configured so the server can still start and be verified without Docker.

## Required setup

1. Copy `.env.example` to `.env` and fill in your PayPal Sandbox credentials.
2. Start PostgreSQL:
   ```bash
   docker compose up -d db
   ```
3. Create and activate a Python virtual environment in `backend`.
4. Install Python dependencies:
   ```bash
   pip install -r backend/requirements.txt
   ```
5. Install frontend dependencies:
   ```bash
   cd frontend && npm install
   ```
6. Start the backend:
   ```bash
   cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
   ```
7. Start the frontend:
   ```bash
   cd frontend && npm run dev -- --host 0.0.0.0
   ```

## Security notes

- PayPal credentials must remain backend-only.
- No secrets are stored in frontend code.
- Sandbox mode is the default and should be used initially.
- Missing Reporting permissions are surfaced as a blocker instead of a simulated success.

## Data requirements

- Actual PayPal API records are imported only when authorization has been completed.
- Transaction IDs are stored in PostgreSQL as unique identifiers.
- Duplicate imports are prevented by unique PayPal transaction IDs.
- Sandbox activity is clearly labeled and never presented as live customer payment data.
- Manual records are kept separate from PayPal API records.
- The app does not insert placeholder transaction data when an API call fails.

## Fraud review rules

The backend analyzes imported transactions for:

- duplicate payments
- unusual amounts
- repeated failed payments
- abnormal frequency
- suspicious payment patterns

Alerts are generated as review alerts only. Transactions are never automatically marked as confirmed fraud.

## Testing

Run:

```bash
cd backend
pytest -q
```

Tests cover:

- PayPal OAuth configuration requirements
- missing Reporting permissions
- duplicate transaction prevention
- review alert generation
- fetch flow handling without secrets

If the PayPal API is not configured, the app clearly reports the blocker instead of disguising that status.
