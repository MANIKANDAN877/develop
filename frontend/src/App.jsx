import { useEffect, useMemo, useState } from "react";
import axios from "axios";

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";
axios.defaults.withCredentials = true;

const emptyFilters = {
  transactionId: "",
  orderId: "",
  amount: "",
  paymentStatus: "all",
};

const statusPalette = {
  success: "success",
  completed: "success",
  s: "success",
  pending: "pending",
  p: "pending",
  failed: "danger",
  denied: "danger",
  canceled: "danger",
  expired: "danger",
  review: "warning",
  resolved: "success",
};

const officialStatusLabels = {
  s: "Successful",
  p: "Pending",
  d: "Denied",
  f: "Failed",
  success: "Successful",
  completed: "Completed",
  pending: "Pending",
  denied: "Denied",
  failed: "Failed",
  canceled: "Canceled",
  expired: "Expired",
};

const valueOrNotProvided = (value) => {
  if (value === null || value === undefined) return "Not provided";
  if (typeof value === "string" && value.trim() === "") return "Not provided";
  return value;
};

const getStatusLabel = (value) => {
  if (value === null || value === undefined || value === "") return "Unknown";
  const key = String(value).trim().toLowerCase();
  return officialStatusLabels[key] || String(value).toUpperCase();
};

const getEnvironmentLabel = (value) => {
  const normalized = String(value || "")
    .trim()
    .toLowerCase();
  if (!normalized) return "Not provided";
  return normalized === "sandbox" ? "Sandbox" : normalized;
};

const moneyValue = (value) => {
  const numeric = Number.parseFloat(value ?? 0);
  return Number.isFinite(numeric) ? numeric : 0;
};

const formatMoney = (value) => {
  const numeric = moneyValue(value);
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(numeric);
};

const toDate = (value) => {
  if (!value) return null;
  const parsed = new Date(value);
  return Number.isNaN(parsed.getTime()) ? null : parsed;
};

function App() {
  const [config, setConfig] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [webhookEvents, setWebhookEvents] = useState([]);
  const [balance, setBalance] = useState(null);
  const [status, setStatus] = useState("Loading dashboard…");
  const [searchState, setSearchState] = useState("idle");
  const [searchError, setSearchError] = useState("");
  const [selectedTransaction, setSelectedTransaction] = useState(null);
  const [aiExplanations, setAiExplanations] = useState({});
  const [filters, setFilters] = useState(emptyFilters);
  const [startDate, setStartDate] = useState("");
  const [endDate, setEndDate] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize] = useState(8);
  const [isLoading, setIsLoading] = useState(true);
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("admin123");
  const [authError, setAuthError] = useState("");

  const verifiedTransactions = useMemo(
    () =>
      (Array.isArray(transactions) ? transactions : []).filter(
        (tx) => (tx.environment || "sandbox").toLowerCase() === "sandbox",
      ),
    [transactions],
  );

  const handleLogin = async (event) => {
    event.preventDefault();
    setAuthError("");

    try {
      const response = await axios.post(
        `${API_URL}/api/auth/login`,
        { username, password },
        { withCredentials: true },
      );
      if (response.data?.status === "ok") {
        setIsAuthenticated(true);
        setStatus("Dashboard authenticated.");
        await loadDashboard();
      }
    } catch (error) {
      setAuthError(
        error.response?.data?.detail ||
          "Authentication failed. Check the dashboard credentials.",
      );
      setIsAuthenticated(false);
    }
  };

  const handleLogout = async () => {
    try {
      await axios.post(`${API_URL}/api/auth/logout`, null, {
        withCredentials: true,
      });
    } catch (error) {
      // Ignore logout errors and clear local auth state.
    } finally {
      setIsAuthenticated(false);
      setAuthError("");
      setStatus("Signed out.");
    }
  };

  const checkAuth = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/auth/me`, {
        withCredentials: true,
      });
      if (response.data?.user) {
        setIsAuthenticated(true);
        return true;
      }
    } catch (error) {
      setIsAuthenticated(false);
    }
    return false;
  };

  const loadDashboard = async () => {
    const authorized = await checkAuth();
    if (!authorized) {
      setIsAuthenticated(false);
      return;
    }

    setIsLoading(true);
    try {
      const [
        configResponse,
        transactionsResponse,
        alertResponse,
        webhookEventsResponse,
        balanceResponse,
      ] = await Promise.all([
        axios.get(`${API_URL}/api/paypal/config-status`, {
          withCredentials: true,
        }),
        axios.get(`${API_URL}/api/paypal/transactions`, {
          withCredentials: true,
        }),
        axios.get(`${API_URL}/api/paypal/alerts`, { withCredentials: true }),
        axios.get(`${API_URL}/api/paypal/webhook-events`, {
          withCredentials: true,
        }),
        axios.get(`${API_URL}/api/paypal/balance`, { withCredentials: true }),
      ]);

      const allTransactions = transactionsResponse.data.results || [];
      const transactionList = allTransactions.filter(
        (tx) => (tx.environment || "sandbox").toLowerCase() === "sandbox",
      );
      setConfig(configResponse.data);
      setTransactions(transactionList);
      setAlerts(alertResponse.data.results || []);
      setWebhookEvents(webhookEventsResponse.data.results || []);
      setBalance(balanceResponse.data);
      setSelectedTransaction(
        (current) => current || transactionList[0] || null,
      );
      setStatus(
        balanceResponse.data.status === "blocked"
          ? "PayPal access is blocked by missing permissions or credentials."
          : "PayPal Sandbox account data available.",
      );
      setSearchState("idle");
      setSearchError("");
    } catch (error) {
      setStatus(
        "Unable to reach the backend API. Start the FastAPI service with the PayPal credentials configured.",
      );
      setSearchState("error");
      setSearchError(
        "Unable to load PayPal Sandbox transactions from the backend.",
      );
    } finally {
      setIsLoading(false);
    }
  };

  const filteredTransactions = useMemo(() => {
    const query = {
      ...filters,
      paymentStatus:
        filters.paymentStatus === "all" ? "" : filters.paymentStatus,
    };

    return verifiedTransactions.filter((tx) => {
      const transactionStatus = (
        tx.payment_status ||
        tx.transaction_status ||
        ""
      )
        .toString()
        .toLowerCase();
      const txDate = toDate(tx.created_at || tx.captured_at);
      const start = startDate ? toDate(startDate) : null;
      const end = endDate ? toDate(endDate) : null;

      const matchesTransactionId =
        !query.transactionId ||
        tx.paypal_transaction_id?.includes(query.transactionId.trim());
      const matchesOrderId =
        !query.orderId ||
        [tx.order_id, tx.parent_transaction_id, tx.invoice_id].some(
          (value) => value && String(value).includes(query.orderId.trim()),
        );
      const matchesAmount =
        !query.amount || moneyValue(tx.amount) === moneyValue(query.amount);
      const matchesPaymentStatus =
        !query.paymentStatus ||
        transactionStatus === query.paymentStatus.toLowerCase();
      const matchesDateStart = !start || !txDate || txDate >= start;
      const matchesDateEnd = !end || !txDate || txDate <= end;

      return (
        matchesTransactionId &&
        matchesOrderId &&
        matchesAmount &&
        matchesPaymentStatus &&
        matchesDateStart &&
        matchesDateEnd
      );
    });
  }, [verifiedTransactions, filters, startDate, endDate]);

  const pageCount = Math.max(
    1,
    Math.ceil(filteredTransactions.length / pageSize),
  );
  const paginatedTransactions = filteredTransactions.slice(
    (page - 1) * pageSize,
    page * pageSize,
  );

  const dashboardStats = useMemo(() => {
    const totalVolume = filteredTransactions.reduce(
      (sum, tx) => sum + moneyValue(tx.amount),
      0,
    );
    const successful = filteredTransactions.filter((tx) => {
      const statusValue = (tx.payment_status || tx.transaction_status || "")
        .toString()
        .toLowerCase();
      return ["s", "success", "completed"].includes(statusValue);
    }).length;
    const pending = filteredTransactions.filter((tx) => {
      const statusValue = (tx.payment_status || tx.transaction_status || "")
        .toString()
        .toLowerCase();
      return ["p", "pending"].includes(statusValue);
    }).length;
    const failed = filteredTransactions.filter((tx) => {
      const statusValue = (tx.payment_status || tx.transaction_status || "")
        .toString()
        .toLowerCase();
      return ["failed", "denied", "canceled", "expired"].includes(statusValue);
    }).length;
    const activeAlerts = alerts.filter(
      (alert) => (alert.status || "review") !== "resolved",
    ).length;

    return {
      totalVolume,
      successful,
      pending,
      failed,
      activeAlerts,
    };
  }, [filteredTransactions, alerts]);

  const chartData = [
    { label: "Successful", value: dashboardStats.successful },
    { label: "Pending", value: dashboardStats.pending },
    { label: "Failed", value: dashboardStats.failed },
  ];

  const handleFieldChange = (event) => {
    const { name, value } = event.target;
    setFilters((previous) => ({ ...previous, [name]: value }));
    setPage(1);
  };

  const searchTransaction = async (event) => {
    event.preventDefault();
    const params = {
      transaction_id: filters.transactionId || undefined,
      order_id: filters.orderId || undefined,
      amount: filters.amount || undefined,
      payment_status:
        filters.paymentStatus !== "all" ? filters.paymentStatus : undefined,
    };

    setSearchState("loading");
    setSearchError("");
    setStatus("Searching the verified PayPal Sandbox records…");

    try {
      const response = await axios.get(
        `${API_URL}/api/paypal/transactions/search`,
        { params, withCredentials: true },
      );
      if (response.data.found) {
        setSelectedTransaction(response.data.transaction);
        setSearchState("success");
        setStatus(
          `Transaction located: ${response.data.transaction.paypal_transaction_id}`,
        );
      } else {
        setSelectedTransaction(null);
        setSearchState("empty");
        setStatus(
          response.data.message ||
            "No matching PayPal Sandbox transaction was found.",
        );
      }
    } catch (error) {
      setSearchState("error");
      setSearchError(
        "Search failed for the supplied PayPal transaction filters.",
      );
      setStatus("Search failed for the supplied PayPal transaction filters.");
    }
  };

  const importTransactions = async () => {
    try {
      const response = await axios.post(
        `${API_URL}/api/paypal/import?start_date=${encodeURIComponent(startDate || "2024-01-01T00:00:00Z")}&end_date=${encodeURIComponent(endDate || "2024-12-31T23:59:59Z")}`,
        null,
        { withCredentials: true },
      );
      setStatus(
        response.data.status === "ok"
          ? `Imported ${response.data.imported_count} transaction(s).`
          : response.data.message,
      );
      if (response.data.status === "ok") {
        await loadDashboard();
      }
    } catch (error) {
      setStatus(
        "Import failed. See the backend logs for the PayPal API error details.",
      );
    }
  };

  const updateAlertStatus = async (alertId, nextStatus) => {
    try {
      const response = await axios.patch(
        `${API_URL}/api/paypal/alerts/${alertId}`,
        null,
        {
          params: { status: nextStatus },
          withCredentials: true,
        },
      );
      setAlerts((current) =>
        current.map((alert) =>
          alert.alert_id === alertId
            ? { ...alert, status: response.data.status }
            : alert,
        ),
      );
      setStatus(`Alert ${alertId} marked as ${response.data.status}.`);
    } catch (error) {
      setStatus("Unable to update the fraud alert status.");
    }
  };

  const fetchAiExplanation = async (alertId) => {
    if (!alertId || aiExplanations[alertId]) return;

    try {
      const response = await axios.post(
        `${API_URL}/api/paypal/alerts/${alertId}/ai-explanation`,
        null,
        { withCredentials: true },
      );
      setAiExplanations((current) => ({
        ...current,
        [alertId]: response.data,
      }));
    } catch (error) {
      setAiExplanations((current) => ({
        ...current,
        [alertId]: {
          status: "unavailable",
          ai_model: "sarvam-105b",
          explanation: "AI explanation unavailable.",
          risk_factors: [],
          recommended_action: "Manual review by a human analyst.",
        },
      }));
    }
  };

  useEffect(() => {
    checkAuth().then((ready) => {
      if (ready) {
        loadDashboard();
      }
    });
  }, []);

  useEffect(() => {
    alerts.forEach((alert) => {
      if (alert.alert_id && !aiExplanations[alert.alert_id]) {
        fetchAiExplanation(alert.alert_id);
      }
    });
  }, [alerts, aiExplanations]);

  if (!isAuthenticated) {
    return (
      <div className="auth-shell">
        <div className="card auth-card">
          <p className="eyebrow">Secure dashboard</p>
          <h1>Sign in</h1>
          <form onSubmit={handleLogin} className="auth-form">
            <label>
              Username
              <input
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
              />
            </label>
            <label>
              Password
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
              />
            </label>
            {authError ? <p className="error-message">{authError}</p> : null}
            <button type="submit" disabled={!username || !password}>
              Authenticate
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <div className="app-shell">
      <header className="topbar">
        <div>
          <p className="eyebrow">PayPal Sandbox</p>
          <h1>Fraud Detection & Payment Finder</h1>
        </div>
        <div className="button-row">
          <button className="secondary-button" onClick={loadDashboard}>
            Refresh data
          </button>
          <button className="secondary-button" onClick={handleLogout}>
            Logout
          </button>
        </div>
      </header>

      <section className="summary-grid">
        <div className="card metric-card">
          <span className="metric-label">Transactions</span>
          <strong>{filteredTransactions.length}</strong>
          <small>Imported records</small>
        </div>
        <div className="card metric-card accent">
          <span className="metric-label">Volume</span>
          <strong>{formatMoney(dashboardStats.totalVolume)}</strong>
          <small>Actual PayPal value</small>
        </div>
        <div className="card metric-card success">
          <span className="metric-label">Successful</span>
          <strong>{dashboardStats.successful}</strong>
          <small>Completed payments</small>
        </div>
        <div className="card metric-card warning">
          <span className="metric-label">Alerts</span>
          <strong>{dashboardStats.activeAlerts}</strong>
          <small>Review queue</small>
        </div>
      </section>

      <section className="monitor-grid">
        <div className="card panel">
          <div className="panel-header">
            <h2>Transaction search</h2>
          </div>

          <form className="filters" onSubmit={searchTransaction}>
            <label>
              Transaction ID
              <input
                name="transactionId"
                value={filters.transactionId}
                onChange={handleFieldChange}
                placeholder="TXN-..."
              />
            </label>
            <label>
              Order ID
              <input
                name="orderId"
                value={filters.orderId}
                onChange={handleFieldChange}
                placeholder="ORDER-..."
              />
            </label>
            <label>
              Amount
              <input
                name="amount"
                value={filters.amount}
                onChange={handleFieldChange}
                placeholder="250.00"
              />
            </label>
            <label>
              Payment status
              <select
                name="paymentStatus"
                value={filters.paymentStatus}
                onChange={handleFieldChange}
              >
                <option value="all">All statuses</option>
                <option value="S">Successful</option>
                <option value="P">Pending</option>
                <option value="D">Denied</option>
                <option value="F">Failed</option>
              </select>
            </label>
            <div className="date-grid">
              <label>
                Start date
                <input
                  type="datetime-local"
                  value={startDate}
                  onChange={(e) => setStartDate(e.target.value)}
                />
              </label>
              <label>
                End date
                <input
                  type="datetime-local"
                  value={endDate}
                  onChange={(e) => setEndDate(e.target.value)}
                />
              </label>
            </div>
            <div className="button-row">
              <button type="submit">Find record</button>
              <button
                type="button"
                className="secondary-button"
                onClick={importTransactions}
              >
                Import history
              </button>
            </div>
          </form>

          <div className={`status-strip ${searchState}`}>
            {searchState === "error"
              ? searchError || status
              : searchState === "loading"
                ? "Searching the verified PayPal Sandbox records…"
                : searchState === "success"
                  ? status
                  : searchState === "empty"
                    ? status
                    : status}
          </div>
        </div>

        <div className="card panel">
          <div className="panel-header">
            <h2>Risk snapshot</h2>
          </div>
          <div className="chart">
            {chartData.map((entry) => (
              <div key={entry.label} className="bar-group">
                <div className="bar-meta">
                  <span>{entry.label}</span>
                  <strong>{entry.value}</strong>
                </div>
                <div className="bar-track">
                  <div
                    className={`bar-fill ${entry.label.toLowerCase()}`}
                    style={{
                      width: `${Math.max(8, (entry.value / Math.max(...chartData.map((item) => item.value), 1)) * 100)}%`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      <section className="table-card card">
        <div className="panel-header">
          <h2>Transaction history</h2>
        </div>

        {isLoading ? (
          <p className="empty-state">
            Loading verified PayPal Sandbox transactions…
          </p>
        ) : paginatedTransactions.length === 0 ? (
          <p className="empty-state">
            No verified PayPal Sandbox transactions match the current filters.
          </p>
        ) : (
          <>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Transaction</th>
                    <th>Order</th>
                    <th>Payer</th>
                    <th>Amount</th>
                    <th>Status</th>
                    <th>Date</th>
                  </tr>
                </thead>
                <tbody>
                  {paginatedTransactions.map((tx) => (
                    <tr
                      key={tx.paypal_transaction_id}
                      onClick={() => setSelectedTransaction(tx)}
                      className={
                        selectedTransaction?.paypal_transaction_id ===
                        tx.paypal_transaction_id
                          ? "selected-row"
                          : ""
                      }
                    >
                      <td>{tx.paypal_transaction_id}</td>
                      <td>
                        {tx.order_id ||
                          tx.parent_transaction_id ||
                          tx.invoice_id ||
                          "—"}
                      </td>
                      <td>
                        {valueOrNotProvided(tx.payer_email || tx.payer_name)}
                      </td>
                      <td>
                        <div className="amount-block">
                          <strong>{formatMoney(tx.amount)}</strong>
                          <small>{valueOrNotProvided(tx.currency)}</small>
                        </div>
                      </td>
                      <td>
                        <div className="status-stack">
                          <span
                            className={`tag ${statusPalette[(tx.payment_status || tx.transaction_status || "").toString().toLowerCase()] || "warning"}`}
                          >
                            {getStatusLabel(
                              tx.payment_status || tx.transaction_status,
                            )}
                          </span>
                          <span className="env-tag">
                            {getEnvironmentLabel(tx.environment)}
                          </span>
                        </div>
                      </td>
                      <td>
                        {tx.created_at
                          ? new Date(tx.created_at).toLocaleString()
                          : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="pagination">
              <button
                type="button"
                disabled={page === 1}
                onClick={() => setPage((current) => Math.max(1, current - 1))}
              >
                Previous
              </button>
              <span>
                Page {page} of {pageCount}
              </span>
              <button
                type="button"
                disabled={page >= pageCount}
                onClick={() =>
                  setPage((current) => Math.min(pageCount, current + 1))
                }
              >
                Next
              </button>
            </div>
          </>
        )}
      </section>

      <section className="alert-panel">
        <div className="card panel">
          <div className="panel-header">
            <h2>Webhook events</h2>
          </div>

          {webhookEvents.length === 0 ? (
            <p className="empty-state">
              No validated PayPal webhook events have been received yet.
            </p>
          ) : (
            <div className="alert-list">
              {webhookEvents.slice(0, 6).map((event) => (
                <article key={event.event_id} className="alert-item">
                  <div>
                    <div className="alert-header">
                      <strong>{event.event_type}</strong>
                      <span
                        className={`tag ${event.verified ? "success" : "danger"}`}
                      >
                        {event.verified ? "Verified" : "Rejected"}
                      </span>
                    </div>
                    <p>{event.summary || "PayPal webhook event"}</p>
                    <small>{event.event_id}</small>
                  </div>
                  <div className="alert-actions">
                    <span className="risk-score">
                      {event.resource_id || "No resource"}
                    </span>
                    <span className="env-tag">{event.status}</span>
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        <div className="card panel">
          <div className="panel-header">
            <h2>Review queue</h2>
          </div>

          {alerts.length === 0 ? (
            <p className="empty-state">
              No suspicious patterns found in the current imported dataset.
            </p>
          ) : (
            <div className="alert-list">
              {alerts.map((alert) => (
                <article
                  key={
                    alert.alert_id ||
                    `${alert.paypal_transaction_id}-${alert.alert_type}`
                  }
                  className="alert-item"
                >
                  <div>
                    <div className="alert-header">
                      <strong>{alert.alert_type}</strong>
                      <span
                        className={`tag ${statusPalette[alert.severity] || "warning"}`}
                      >
                        {alert.severity}
                      </span>
                    </div>
                    <p>{alert.message}</p>
                    <small>{alert.paypal_transaction_id}</small>
                  </div>

                  <div className="alert-actions">
                    <span className="risk-score">
                      Risk {alert.risk_score ?? 0}
                    </span>
                    <select
                      value={alert.status || "review"}
                      onChange={(event) =>
                        updateAlertStatus(alert.alert_id, event.target.value)
                      }
                    >
                      <option value="review">Review</option>
                      <option value="resolved">Resolved</option>
                    </select>
                  </div>

                  <div className="ai-explanation-panel">
                    <strong>AI explanation</strong>
                    {aiExplanations[alert.alert_id] ? (
                      <>
                        <p>
                          {aiExplanations[alert.alert_id].explanation ||
                            "AI explanation unavailable."}
                        </p>
                        <ul>
                          {(
                            aiExplanations[alert.alert_id].risk_factors || []
                          ).map((factor) => (
                            <li key={factor}>{factor}</li>
                          ))}
                        </ul>
                        <small>
                          Recommended action:{" "}
                          {aiExplanations[alert.alert_id].recommended_action ||
                            "Manual review by a human analyst."}
                        </small>
                        <small className="ai-model-tag">
                          Model:{" "}
                          {aiExplanations[alert.alert_id].ai_model ||
                            "sarvam-105b"}
                        </small>
                      </>
                    ) : (
                      <p>Loading AI explanation…</p>
                    )}
                  </div>
                </article>
              ))}
            </div>
          )}
        </div>

        <div className="card panel detail-panel">
          <div className="panel-header">
            <h2>Selected transaction</h2>
          </div>

          {selectedTransaction ? (
            <div className="detail-content">
              <div className="detail-row">
                <span>Transaction ID</span>
                <strong>{selectedTransaction.paypal_transaction_id}</strong>
              </div>
              <div className="detail-row">
                <span>Order ID</span>
                <strong>
                  {selectedTransaction.order_id ||
                    selectedTransaction.parent_transaction_id ||
                    selectedTransaction.invoice_id ||
                    "—"}
                </strong>
              </div>
              <div className="detail-row">
                <span>Amount</span>
                <strong>{formatMoney(selectedTransaction.amount)}</strong>
              </div>
              <div className="detail-row">
                <span>Currency</span>
                <strong>
                  {valueOrNotProvided(selectedTransaction.currency)}
                </strong>
              </div>
              <div className="detail-row">
                <span>Status</span>
                <strong>
                  {getStatusLabel(
                    selectedTransaction.payment_status ||
                      selectedTransaction.transaction_status,
                  )}
                </strong>
              </div>
              <div className="detail-row">
                <span>Environment</span>
                <strong>
                  {getEnvironmentLabel(selectedTransaction.environment)}
                </strong>
              </div>
              <div className="detail-row">
                <span>Payer name</span>
                <strong>
                  {valueOrNotProvided(selectedTransaction.payer_name)}
                </strong>
              </div>
              <div className="detail-row">
                <span>Payer email</span>
                <strong>
                  {valueOrNotProvided(selectedTransaction.payer_email)}
                </strong>
              </div>
              <div className="detail-row">
                <span>Created</span>
                <strong>
                  {selectedTransaction.created_at
                    ? new Date(selectedTransaction.created_at).toLocaleString()
                    : "—"}
                </strong>
              </div>
            </div>
          ) : (
            <p className="empty-state">No PayPal transaction selected.</p>
          )}
        </div>
      </section>
    </div>
  );
}

export default App;
