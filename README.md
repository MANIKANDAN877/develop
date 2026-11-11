# PayPal Fraud Detection & Sandbox Payment Monitoring

This project is a sandbox-only PayPal merchant monitoring dashboard built around a FastAPI backend and a React + Vite frontend. It is designed to help a merchant review Sandbox account balance, imported PayPal transactions, buyer payment activity, webhook events, and fraud risk without exposing any secrets in the browser.

## Project goal

The system is intentionally limited to sandbox-safe review workflows. It does not perform live money movement, and it does not enable real PayPal live payouts. The application focuses on:

- reading the merchant sandbox balance from the official PayPal Reporting API
- validating OAuth access tokens securely on the backend
- importing and reviewing sandbox transaction history
- showing funding status and actual available balance
- flagging suspicious customer patterns for review only
- scoring synthetic fraud-risk signals using a Random Forest model
- exposing a clear merchant dashboard without leaking credentials

## Key security and safety rules

- Sandbox mode is the default and is the only supported operational mode.
- Real money transfers are not enabled.
- Live payout calls are blocked by configuration.
- PayPal client IDs and secrets stay in backend environment variables only.
- The frontend never stores or exposes credentials.
- The dashboard distinguishes sandbox data from live payment data.

## Architecture

- Backend: FastAPI service in backend/app
- Frontend: Vite + React dashboard in frontend/src
- Database: SQLite fallback for local validation; PostgreSQL-ready for production use
- PayPal integration: OAuth token retrieval, sandbox balance checks, transaction imports, payout validation, webhook status checks
- Fraud module: rule-based review logic plus a Random Forest model trained on synthetic data only

## Project structure

- backend/app: core FastAPI app, PayPal logic, fraud logic, database models
- backend/tests: backend validation suite
- frontend/src: dashboard UI and test files
- frontend/package.json: frontend scripts and dependencies
- docker-compose.yml: PostgreSQL service definition
- README.md: project overview and run instructions
- render.yaml: deployment configuration
- DEPLOYMENT.md: deployment notes
- .env.example: example environment template

## Technology stack

- Python 3.13
- FastAPI
- SQLAlchemy
- Requests
- scikit-learn
- joblib
- React 18
- Vite
- Vitest
- PayPal Sandbox APIs

## Environment setup

1. Copy the backend example environment file to a real environment file and populate the PayPal sandbox credentials.
2. Ensure the backend uses the correct PayPal mode and base URL for Sandbox only.
3. Install Python packages:
   ```bash
   cd backend
   python -m pip install -r requirements.txt
   ```
4. Install frontend dependencies:
   ```bash
   cd frontend
   npm install
   ```

## Run the application

Start the backend:

```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Start the frontend:

```bash
cd frontend
npm run dev -- --host 0.0.0.0
```

Then open the frontend in the browser and confirm the backend is reachable at:

- http://localhost:8000/docs
- http://localhost:5173

## Verification and tests

Run the backend tests:

```bash
cd backend
pytest -q
```

Run the frontend tests:

```bash
cd frontend
npm test
```

The project is designed to validate the following behavior honestly:

- sandbox mode configuration and OAuth requirements
- balance retrieval and blocked access handling
- duplicate transaction prevention
- fraud review alert generation
- payout safety checks in sandbox mode only
- frontend dashboard rendering and balance refresh flows

## Fraud detection notes

This project includes a synthetic Random Forest model for transaction risk scoring. The model is trained only on generated synthetic data and is clearly labeled as synthetic. It is used for review support and risk categorization only. Real PayPal Sandbox transactions are not used as training data, and synthetic accuracy metrics are not presented as real-world fraud-detection claims.

Risk labels:

- 0–30: LOW RISK
- 31–70: MEDIUM RISK
- 71–100: HIGH RISK

## Submission and security checklist

- Keep PayPal credentials in backend environment variables only.
- Never commit .env files to source control.
- Keep sandbox mode enabled.
- Do not enable live payouts.
- Do not claim successful real-money transfers when the app is in sandbox mode.
- Keep all secret-bearing files out of any submission ZIP or archive.

## Limitations

This application is built for sandbox review, testing, and merchant monitoring. It is not a production-live payment engine and should not be treated as an actual live transfer system while the live payout flag remains disabled.
