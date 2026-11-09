# PayPal Fraud Detection Deployment Guide

This project is prepared for deployment without changing the working application behavior. The app remains in PayPal Sandbox mode unless you explicitly change environment variables during deployment.

## Secret handling

- Do not commit or expose real secrets.
- Keep your real values in the hosting provider dashboard and in a local non-committed `.env` file.
- The repository has `.env` and secret-file exclusions configured in `.gitignore`.
- Example files are provided as `.env.example` templates only.

## Required environment variables

### Backend (`backend/.env.example`)

- `APP_ENV=production`
- `ALLOW_LOCAL_DEV_UNAUTH=false`
- `AUTH_SECRET_KEY=<strong-random-secret>`
- `DASHBOARD_USERNAME=<dashboard-user>`
- `DASHBOARD_PASSWORD=<strong-dashboard-password>`
- `SESSION_TOKEN_TTL_MINUTES=120`
- `RATE_LIMIT_PER_MINUTE=60`
- `FRONTEND_URL=https://<frontend-domain>`
- `BACKEND_URL=https://<backend-domain>`
- `CORS_ALLOWED_ORIGINS=https://<frontend-domain>,https://localhost:5173,http://localhost:5173`
- `PAYPAL_MODE=sandbox`
- `PAYPAL_CLIENT_ID=<sandbox-client-id>`
- `PAYPAL_CLIENT_SECRET=<sandbox-client-secret>`
- `PAYPAL_API_BASE=https://api-m.sandbox.paypal.com`
- `PAYPAL_WEB_BASE=https://www.sandbox.paypal.com`
- `PAYPAL_WEBHOOK_ID=<sandbox-webhook-id>`
- `DATABASE_URL=postgresql://user:password@host:5432/paypal_fraud`
- `SARVAM_API_KEY=<sarvam-api-key>`
- `SARVAM_MODEL=sarvam-105b`
- `SARVAM_API_BASE=https://api.sarvam.ai`

### Frontend (`frontend/.env.example`)

- `VITE_API_URL=https://<backend-domain>`
- `VITE_APP_ENV=production`

## Render backend configuration

Create a web service on Render using the project root `render.yaml` or create the service manually with:

- Runtime: Python
- Root directory: `backend`
- Build command: `pip install -r requirements.txt`
- Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`
- Health check path: `/health`

The backend health endpoint is available at:

- `https://<backend-domain>/health`

Expected payload:

```json
{
  "status": "ok",
  "environment": "sandbox",
  "sandbox_mode": true
}
```

## Vercel frontend configuration

Use the project root `frontend/vercel.json` and set the following Vercel environment variable:

- `VITE_API_URL=https://<backend-domain>`

The frontend project should be deployed from the `frontend` directory with Vite build output from `dist`.

## Cookie compatibility for separate domains

Authentication uses cookies with `httpOnly` and environment-aware cookie policy. In production, when the frontend and backend are on different domains, the cookie is emitted with `SameSite=None` and `Secure` to permit browser cross-domain session authentication.

For local single-domain development, the app keeps the standard `SameSite=Lax` behavior.

## PayPal Sandbox webhook URL

Set your public webhook endpoint to:

```text
https://<backend-domain>/api/paypal/webhooks
```

The webhook route supports:

- `PAYMENT.CAPTURE.COMPLETED`
- `PAYMENT.CAPTURE.DENIED`
- `PAYMENT.CAPTURE.REFUNDED`

The backend verifies every request with PayPal's `/v1/notifications/verify-webhook-signature` endpoint before storing or processing events.

## SQLite to PostgreSQL migration notes

The app currently defaults to SQLite for local development, but the code is designed to use a SQLAlchemy `DATABASE_URL` environment variable for deployment. This is compatible with PostgreSQL in Render.

Required migration guidance:

1. Set `DATABASE_URL` to a PostgreSQL connection string in Render.
2. Ensure all database tables are created or migrated in Postgres.
3. Export local SQLite data if needed, then import to Postgres using a migration tool such as `pgloader`, `sqlite3` + SQL dumps, or a one-time ETL script.
4. Avoid relying on SQLite-only configurations such as `StaticPool` and `check_same_thread`. Those are local-safe and skipped automatically when the connection is not SQLite.
5. Keep the PayPal transaction and fraud alert schemas consistent across both environments.

## Health-check verification

Run the following check after deployment:

```bash
curl -f https://<backend-domain>/health
```

If the service is healthy, the response should include `status: "ok"`.

## Exact remaining deployment steps

1. Create the Render backend service and add your backend environment variables from `backend/.env.example`.
2. Set `PAYPAL_MODE=sandbox`, `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`, and `PAYPAL_WEBHOOK_ID` to your PayPal Sandbox values.
3. Set `DATABASE_URL` to the Render Postgres URL and ensure the app can connect.
4. Set `SARVAM_API_KEY` and `SARVAM_MODEL` in the backend environment.
5. Add the backend domain to the `CORS_ALLOWED_ORIGINS` value in Render.
6. Deploy the backend and confirm `/health` returns `200`.
7. Create a Vercel frontend project from the `frontend` directory.
8. Add `VITE_API_URL` in Vercel and set the backend URL.
9. Register the public PayPal Sandbox webhook URL: `https://<backend-domain>/api/paypal/webhooks`.
10. Confirm the dashboard loads and the auth cookie is accepted with the separate frontend/backend domains.
11. Validate the app without switching to PayPal Live.

## Test and build results

Backend verification:

```bash
cd backend
python -m pytest -q
```

Actual result:

- `14 passed, 3 warnings in 2.41s`

Frontend verification:

```bash
cd frontend
npm run build
```

Actual result:

- `✓ built in 1.79s`

The warnings are non-blocking framework deprecations and do not affect application functionality.
