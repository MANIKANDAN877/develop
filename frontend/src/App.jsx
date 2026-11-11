import { useEffect, useMemo, useState } from "react";
import axios from "axios";

const API_URL = (
  import.meta.env.VITE_API_URL || "http://localhost:8000"
).replace(/\/$/, "");
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

const getBalanceEntry = (payload) => {
  const balanceList = Array.isArray(payload?.balances)
    ? payload.balances.filter(Boolean)
    : [];

  if (balanceList.length === 0) {
    return payload?.total_balance ||
      payload?.available_balance ||
      payload?.withheld_balance
      ? {
          currency: payload?.currency || "USD",
          total: payload.total_balance || {},
          available: payload.available_balance || {},
          withheld: payload.withheld_balance || {},
          accountStatus: payload?.account_status || payload?.status || "ACTIVE",
          accountId: payload?.account_id || null,
          lastUpdated:
            payload?.last_updated ||
            payload?.last_refresh_time ||
            payload?.as_of_time ||
            null,
        }
      : null;
  }

  const latestEntry = [...balanceList].sort((left, right) => {
    const leftTime = new Date(left.last_updated || left.as_of || 0).getTime();
    const rightTime = new Date(
      right.last_updated || right.as_of || 0,
    ).getTime();
    return rightTime - leftTime;
  })[0];

  return {
    currency: latestEntry?.currency || payload?.currency || "USD",
    total: latestEntry?.total_balance || {},
    available: latestEntry?.available_balance || {},
    withheld: latestEntry?.withheld_balance || {},
    accountStatus: payload?.account_status || payload?.status || "ACTIVE",
    accountId: payload?.account_id || null,
    lastUpdated:
      latestEntry?.last_updated ||
      payload?.last_updated ||
      payload?.last_refresh_time ||
      payload?.as_of_time ||
      null,
  };
};

const isEligibleCustomerPayment = (tx) => {
  if (!tx) return false;

  const eventCode = getTransactionEventCode(tx);
  if (!eventCode || NON_PAYMENT_EVENT_CODES.has(eventCode)) {
    return false;
  }

  const amount = Number.parseFloat(tx.amount ?? 0);
  if (!Number.isFinite(amount) || amount <= 0) {
    return false;
  }

  const orderReference = [tx.order_id, tx.parent_transaction_id, tx.invoice_id]
    .filter(Boolean)
    .join("");
  const payerReference = [tx.payer_email, tx.payer_name]
    .filter(Boolean)
    .join("");

  if (!payerReference && !orderReference) {
    return false;
  }

  return true;
};

const formatTransactionEventCode = (value) => {
  const code = String(value || "")
    .trim()
    .toUpperCase();
  if (!code) return "Unknown";
  if (code === "T1900") return "Account correction";
  if (code === "PAYMENT") return "Payment";
  return code;
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

const getPayPalApprovalToken = () => {
  if (typeof window === "undefined") return null;
  const params = new URLSearchParams(window.location.search);
  const token =
    params.get("token") || params.get("orderID") || params.get("paymentId");
  return token || null;
};

function App() {
  const [config, setConfig] = useState(null);
  const [transactions, setTransactions] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [webhookEvents, setWebhookEvents] = useState([]);
  const [balance, setBalance] = useState(null);
  const [buyerPayment, setBuyerPayment] = useState(null);
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
  const [balanceError, setBalanceError] = useState("");
  const [checkoutAmount, setCheckoutAmount] = useState("1.00");
  const [checkoutOrderId, setCheckoutOrderId] = useState("");
  const [checkoutApprovalUrl, setCheckoutApprovalUrl] = useState("");
  const [checkoutStatus, setCheckoutStatus] = useState("");
  const [checkoutError, setCheckoutError] = useState("");
  const [payoutRecipient, setPayoutRecipient] = useState("");
  const [payoutAmount, setPayoutAmount] = useState("1.00");
  const [payoutCurrency, setPayoutCurrency] = useState("USD");
  const [payoutNote, setPayoutNote] = useState("PayPal payout from dashboard");
  const [payoutStatus, setPayoutStatus] = useState("");
  const [payoutError, setPayoutError] = useState("");
  const [payoutDetails, setPayoutDetails] = useState(null);
  const [mlAnalytics, setMlAnalytics] = useState(null);

  const verifiedTransactions = useMemo(
    () =>
      (Array.isArray(transactions) ? transactions : []).filter(
        (tx) => (tx.environment || "sandbox").toLowerCase() === "sandbox",
      ),
    [transactions],
  );

  const loadDashboard = async () => {
    setIsLoading(true);
    try {
      const [
        configResponse,
        transactionsResponse,
        alertResponse,
        webhookEventsResponse,
        balanceResponse,
        analyticsResponse,
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
        axios.get(`${API_URL}/api/paypal/fraud/analytics`, {
          withCredentials: true,
        }),
      ]);

      const allTransactions = transactionsResponse.data.results || [];
      const transactionList = allTransactions.filter(
        (tx) => (tx.environment || "sandbox").toLowerCase() === "sandbox",
      );
      const nextBalance = balanceResponse.data || null;
      const payload = nextBalance?.payload || nextBalance?.balance || null;
      const hasFreshBalance =
        payload &&
        ((Array.isArray(payload.balances) && payload.balances.length > 0) ||
          payload.total_balance ||
          payload.available_balance ||
          payload.withheld_balance);

      const latestCompletedPayment = [...transactionList]
        .filter(
          (tx) =>
            (tx.payment_status || tx.transaction_status || "")
              .toString()
              .trim()
              .toLowerCase() === "completed",
        )
        .sort((left, right) => {
          const leftTime = new Date(
            left.created_at || left.captured_at || 0,
          ).getTime();
          const rightTime = new Date(
            right.created_at || right.captured_at || 0,
          ).getTime();
          return rightTime - leftTime;
        })[0];

      setConfig(configResponse.data);
      setTransactions(transactionList);
      setAlerts(alertResponse.data.results || []);
      setWebhookEvents(webhookEventsResponse.data.results || []);
      setBalance(nextBalance);
      setMlAnalytics(analyticsResponse?.data || null);
      setBuyerPayment((currentBuyerPayment) => {
        if (latestCompletedPayment) {
          return {
            amount: latestCompletedPayment.amount,
            currency: latestCompletedPayment.currency || "USD",
            capture_id:
              latestCompletedPayment.paypal_transaction_id ||
              latestCompletedPayment.id ||
              "N/A",
            transaction_id:
              latestCompletedPayment.paypal_transaction_id ||
              latestCompletedPayment.id ||
              "N/A",
            payment_status:
              latestCompletedPayment.payment_status ||
              latestCompletedPayment.transaction_status ||
              "completed",
            order_id: latestCompletedPayment.order_id || null,
            created_at: latestCompletedPayment.created_at || null,
          };
        }

        if (
          currentBuyerPayment &&
          (currentBuyerPayment.payment_status || "")
            .toString()
            .toUpperCase() === "COMPLETED"
        ) {
          return currentBuyerPayment;
        }

        return null;
      });
      setBalanceError(
        nextBalance?.status === "blocked"
          ? nextBalance.message || "PayPal balance request failed."
          : !hasFreshBalance
            ? "Fresh PayPal balance data is not available yet. The Reporting API has not returned an updated sandbox balance."
            : "",
      );
      setSelectedTransaction(
        (current) => current || transactionList[0] || null,
      );
      setStatus(
        nextBalance?.status === "blocked"
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

  const refreshAccountBalance = async () => {
    try {
      const response = await axios.get(`${API_URL}/api/paypal/balance`, {
        withCredentials: true,
      });
      const nextBalance = response.data || null;
      const payload = nextBalance?.payload || nextBalance?.balance || null;
      const hasFreshBalance =
        payload &&
        ((Array.isArray(payload.balances) && payload.balances.length > 0) ||
          payload.total_balance ||
          payload.available_balance ||
          payload.withheld_balance);

      setBalance(nextBalance);
      setBalanceError(
        nextBalance?.status === "blocked"
          ? nextBalance.message || "PayPal balance request failed."
          : !hasFreshBalance
            ? "Fresh PayPal balance data is not available yet. The Reporting API has not returned an updated sandbox balance."
            : "",
      );
      return nextBalance;
    } catch (error) {
      setBalanceError(
        "Unable to refresh the PayPal Sandbox balance right now.",
      );
      return null;
    }
  };

  const createCheckoutPayment = async (event) => {
    event.preventDefault();
    setCheckoutError("");
    setCheckoutStatus("Creating the PayPal checkout order…");

    try {
      const response = await axios.post(
        `${API_URL}/api/paypal/orders`,
        { amount: checkoutAmount, currency: "USD" },
        { withCredentials: true },
      );

      const approvalUrl = response.data?.approval_url;
      const orderId = response.data?.order_id;

      if (!approvalUrl) {
        throw new Error(
          response.data?.message ||
            "The PayPal approval link was not returned for this checkout.",
        );
      }

      setCheckoutOrderId(orderId || "");
      setCheckoutApprovalUrl(approvalUrl);
      setCheckoutStatus(
        "Buyer approval required. Complete the PayPal Sandbox payment in the opened window.",
      );
      window.open(approvalUrl, "_blank", "noopener,noreferrer");
    } catch (error) {
      setCheckoutError(
        error.response?.data?.detail ||
          error.message ||
          "Unable to create the PayPal Sandbox checkout order.",
      );
      setCheckoutStatus("Order creation failed.");
    }
  };

  const captureApprovedOrder = async (providedOrderId = checkoutOrderId) => {
    const orderToCapture = providedOrderId || checkoutOrderId;
    if (!orderToCapture) {
      setCheckoutError("Create an order first and complete buyer approval.");
      setCheckoutStatus(
        "Capture blocked because no approved order is available.",
      );
      return;
    }

    setCheckoutError("");
    setCheckoutStatus("Capturing the approved PayPal order…");

    try {
      const response = await axios.post(
        `${API_URL}/api/paypal/orders/${orderToCapture}/capture`,
        null,
        { withCredentials: true },
      );

      if (response.data?.paypal_status !== "COMPLETED") {
        throw new Error(
          response.data?.message ||
            "The PayPal capture did not finish as COMPLETED.",
        );
      }

      const completedBuyerPayment = {
        amount:
          response.data?.amount ||
          response.data?.result?.purchase_units?.[0]?.payments?.captures?.[0]
            ?.amount?.value ||
          "1.00",
        currency:
          response.data?.currency ||
          response.data?.result?.purchase_units?.[0]?.payments?.captures?.[0]
            ?.amount?.currency_code ||
          "USD",
        capture_id:
          response.data?.capture_id ||
          response.data?.result?.purchase_units?.[0]?.payments?.captures?.[0]
            ?.id ||
          "N/A",
        transaction_id:
          response.data?.transaction_id ||
          response.data?.capture_id ||
          response.data?.result?.purchase_units?.[0]?.payments?.captures?.[0]
            ?.id ||
          "N/A",
        payment_status: response.data?.paypal_status || "COMPLETED",
        order_id: orderToCapture,
        created_at: new Date().toISOString(),
      };

      setBuyerPayment(completedBuyerPayment);
      setCheckoutStatus(
        `Capture completed. The seller reporting balance is being refreshed and the buyer payment activity is confirmed.`,
      );
      setCheckoutApprovalUrl("");
      setCheckoutOrderId("");
      if (typeof window !== "undefined" && window.history?.replaceState) {
        window.history.replaceState({}, "", window.location.pathname);
      }
      await refreshAccountBalance();
      await loadDashboard();
    } catch (error) {
      const message =
        error.response?.data?.detail ||
        error.message ||
        "The PayPal capture did not complete successfully.";
      setCheckoutError(message);
      setCheckoutStatus("Capture failed.");
    }
  };

  const fetchPayoutStatus = async (batchId) => {
    const normalizedBatchId = String(batchId || "").trim();
    if (!normalizedBatchId) {
      return null;
    }

    try {
      const response = await axios.get(
        `${API_URL}/api/paypal/payouts/${encodeURIComponent(normalizedBatchId)}`,
        { withCredentials: true },
      );

      const nextDetails = {
        batchId: response.data?.batch_id || normalizedBatchId,
        itemId: response.data?.item_id || "N/A",
        recipient: response.data?.recipient || "N/A",
        amount: response.data?.amount || "0.00",
        currency: response.data?.currency || payoutCurrency,
        status:
          response.data?.payout_status || response.data?.status || "PENDING",
      };
      setPayoutDetails(nextDetails);
      return nextDetails;
    } catch (error) {
      setPayoutError(
        error.response?.data?.detail ||
          error.message ||
          "Unable to check the PayPal payout status.",
      );
      return null;
    }
  };

  const sendPayout = async (event) => {
    event.preventDefault();
    if (!payoutRecipient || !payoutAmount) {
      setPayoutError("Provide a valid recipient PayPal email and amount.");
      setPayoutStatus("Payout blocked by missing values.");
      return;
    }

    const payoutMode = String(config?.mode || "sandbox").toLowerCase();
    const confirmMessage =
      payoutMode === "live"
        ? "This will send a real PayPal payout from the live account. Confirm that the recipient, amount, and country restrictions are correct before continuing."
        : `This sandbox payout will send ${payoutAmount} ${payoutCurrency} to ${payoutRecipient}. Confirm before continuing.`;

    const confirmed = window.confirm(confirmMessage);
    if (!confirmed) {
      setPayoutStatus(
        payoutMode === "live"
          ? "Live payout cancelled by the user."
          : "Sandbox payout cancelled by the user.",
      );
      setPayoutError("");
      return;
    }

    setPayoutError("");
    setPayoutStatus("Submitting the PayPal payout request…");

    try {
      const response = await axios.post(
        `${API_URL}/api/paypal/payouts`,
        {
          recipient_email: payoutRecipient,
          amount: payoutAmount,
          currency: payoutCurrency,
          note: payoutNote || "PayPal payout from dashboard",
        },
        { withCredentials: true },
      );

      const payoutStatusValue = String(
        response.data?.payout_status || response.data?.status || "PENDING",
      ).toUpperCase();
      const batchId = response.data?.batch_id;

      if (batchId) {
        const statusDetails = await fetchPayoutStatus(batchId);
        if (statusDetails) {
          setPayoutDetails(statusDetails);
        }
      }

      if (payoutStatusValue === "SUCCESS") {
        setPayoutStatus(
          response.data?.message || "PayPal payout confirmed as successful.",
        );
        setPayoutRecipient("");
        setPayoutAmount("1.00");
        setPayoutNote("PayPal payout from dashboard");
        await refreshAccountBalance();
        await loadDashboard();
        return;
      }

      if (payoutStatusValue === "FAILED") {
        setPayoutError(
          response.data?.message || "PayPal payout returned a FAILED status.",
        );
        setPayoutStatus("PayPal payout failed.");
        return;
      }

      setPayoutStatus(
        response.data?.message ||
          "PayPal payout submitted and is pending confirmation.",
      );
    } catch (error) {
      setPayoutError(
        error.response?.data?.detail ||
          error.message ||
          "Unable to submit the PayPal payout.",
      );
      setPayoutStatus("PayPal payout request failed.");
    }
  };

  const balanceEntry = useMemo(
    () => getBalanceEntry(balance?.payload),
    [balance],
  );

  const fundingStatus = useMemo(() => {
    const availableValue = Number.parseFloat(
      balanceEntry?.available?.value ??
        balanceEntry?.available_balance?.value ??
        0,
    );
    return Number.isFinite(availableValue) && availableValue > 0
      ? "FUNDED"
      : "UNFUNDED";
  }, [balanceEntry]);

  const fundingMessage = useMemo(() => {
    const availableValue = Number.parseFloat(
      balanceEntry?.available?.value ??
        balanceEntry?.available_balance?.value ??
        0,
    );
    if (Number.isFinite(availableValue) && availableValue > 0) {
      return "PayPal Sandbox funding is ready for payout testing.";
    }
    return "Awaiting test payment to fund this sandbox business account.";
  }, [balanceEntry]);

  const eligiblePaymentTransactions = useMemo(
    () => verifiedTransactions.filter(isEligibleCustomerPayment),
    [verifiedTransactions],
  );

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
    const totalVolume = eligiblePaymentTransactions.reduce(
      (sum, tx) => sum + moneyValue(tx.amount),
      0,
    );
    const successful = eligiblePaymentTransactions.filter((tx) => {
      const statusValue = (tx.payment_status || tx.transaction_status || "")
        .toString()
        .toLowerCase();
      return SUCCESSFUL_PAYMENT_STATUSES.has(statusValue);
    }).length;
    const pending = eligiblePaymentTransactions.filter((tx) => {
      const statusValue = (tx.payment_status || tx.transaction_status || "")
        .toString()
        .toLowerCase();
      return ["p", "pending"].includes(statusValue);
    }).length;
    const failed = eligiblePaymentTransactions.filter((tx) => {
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
  }, [eligiblePaymentTransactions, alerts]);

  const chartData = [
    { label: "Successful", value: dashboardStats.successful },
    { label: "Pending", value: dashboardStats.pending },
    { label: "Failed", value: dashboardStats.failed },
  ];

  const mlDistribution = mlAnalytics?.summary?.risk_distribution || {
    "LOW RISK": 0,
    "MEDIUM RISK": 0,
    "HIGH RISK": 0,
  };

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
    void loadDashboard();
  }, []);

  useEffect(() => {
    const token = getPayPalApprovalToken();
    if (!token || checkoutOrderId === token) return;

    setCheckoutOrderId(token);
    setCheckoutApprovalUrl(
      `https://www.sandbox.paypal.com/checkoutnow?token=${token}`,
    );
    setCheckoutStatus(
      "Buyer approval detected. Capturing the approved PayPal order…",
    );
    void captureApprovedOrder(token);
  }, [checkoutOrderId]);

  useEffect(() => {
    alerts.forEach((alert) => {
      if (alert.alert_id && !aiExplanations[alert.alert_id]) {
        fetchAiExplanation(alert.alert_id);
      }
    });
  }, [alerts, aiExplanations]);

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
        </div>
      </header>

      <section className="summary-grid">
        <div className="card metric-card">
          <span className="metric-label">Transactions</span>
          <strong>{eligiblePaymentTransactions.length}</strong>
          <small>Eligible customer payments</small>
        </div>
        <div className="card metric-card accent">
          <span className="metric-label">Volume</span>
          <strong>{formatMoney(dashboardStats.totalVolume)}</strong>
          <small>Eligible payment volume</small>
        </div>
        <div className="card metric-card success">
          <span className="metric-label">Successful</span>
          <strong>{dashboardStats.successful}</strong>
          <small>Completed customer payments</small>
        </div>
        <div className="card metric-card warning">
          <span className="metric-label">Alerts</span>
          <strong>{dashboardStats.activeAlerts}</strong>
          <small>Review queue</small>
        </div>
      </section>

      <section className="summary-grid">
        <div className="card panel balance-panel">
          <div className="panel-header">
            <h2>Sandbox Funding Status</h2>
            <div className="button-row">
              <button
                className="secondary-button"
                onClick={refreshAccountBalance}
                disabled={isLoading}
              >
                Refresh Balance
              </button>
            </div>
          </div>

          {isLoading ? (
            <p className="empty-state">Loading sandbox funding status…</p>
          ) : !balanceEntry ? (
            <p className="empty-state">
              No live PayPal sandbox balance has been returned yet.
            </p>
          ) : (
            <div className="balance-list">
              <div className="balance-row">
                <span>Business account status</span>
                <strong>{balanceEntry.accountStatus || "ACTIVE"}</strong>
              </div>
              <div className="balance-row">
                <span>Actual available balance</span>
                <strong>
                  {formatMoney(balanceEntry.available?.value || 0)}
                </strong>
              </div>
              <div className="balance-row">
                <span>Currency</span>
                <strong>{balanceEntry.currency}</strong>
              </div>
              <div className="balance-row">
                <span>Funding status</span>
                <strong>{fundingStatus}</strong>
              </div>
              <div className="balance-row">
                <span>Last balance update</span>
                <strong>
                  {balanceEntry.lastUpdated
                    ? new Date(balanceEntry.lastUpdated).toLocaleString()
                    : "Not provided"}
                </strong>
              </div>
            </div>
          )}

          <p className="empty-state" style={{ marginTop: "1rem" }}>
            {fundingMessage}
          </p>
        </div>

        <div className="card panel">
          <div className="panel-header">
            <h2>Sandbox buyer checkout</h2>
          </div>

          <form className="filters" onSubmit={createCheckoutPayment}>
            <label>
              Amount
              <input
                type="number"
                min="0.01"
                step="0.01"
                value={checkoutAmount}
                onChange={(event) => setCheckoutAmount(event.target.value)}
                placeholder="1.00"
              />
            </label>
            <label>
              Currency
              <input value="USD" readOnly />
            </label>
            <div className="button-row">
              <button type="submit" disabled={!checkoutAmount}>
                Create order
              </button>
              {checkoutApprovalUrl ? (
                <button
                  type="button"
                  className="secondary-button"
                  onClick={() =>
                    window.open(
                      checkoutApprovalUrl,
                      "_blank",
                      "noopener,noreferrer",
                    )
                  }
                >
                  Approve payment
                </button>
              ) : null}
              <button
                type="button"
                className="secondary-button"
                onClick={() => captureApprovedOrder()}
                disabled={!checkoutOrderId}
              >
                Capture approved order
              </button>
            </div>
          </form>

          {checkoutOrderId ? (
            <div className="detail-content">
              <div className="detail-row">
                <span>Order ID</span>
                <strong>{checkoutOrderId}</strong>
              </div>
            </div>
          ) : null}

          {checkoutApprovalUrl ? (
            <p>
              <a href={checkoutApprovalUrl} target="_blank" rel="noreferrer">
                Open PayPal Sandbox approval page
              </a>
            </p>
          ) : null}

          {checkoutError || checkoutStatus ? (
            <div
              className={`status-strip ${checkoutError ? "error" : "success"}`}
            >
              {checkoutError || checkoutStatus}
            </div>
          ) : null}
        </div>

        <div className="card panel">
          <div className="panel-header">
            <h2>Send Money</h2>
          </div>

          <form className="filters" onSubmit={sendPayout}>
            <label>
              Recipient Sandbox email
              <input
                type="email"
                value={payoutRecipient}
                onChange={(event) => setPayoutRecipient(event.target.value)}
                placeholder="buyer@example.com"
              />
            </label>
            <label>
              Amount
              <input
                type="number"
                min="0.01"
                step="0.01"
                value={payoutAmount}
                onChange={(event) => setPayoutAmount(event.target.value)}
                placeholder="25.00"
              />
            </label>
            <label>
              Currency
              <select
                value={payoutCurrency}
                onChange={(event) => setPayoutCurrency(event.target.value)}
              >
                <option value="USD">USD</option>
                <option value="EUR">EUR</option>
                <option value="GBP">GBP</option>
                <option value="INR">INR</option>
              </select>
            </label>
            <label>
              Note
              <input
                value={payoutNote}
                onChange={(event) => setPayoutNote(event.target.value)}
                placeholder="PayPal payout from dashboard"
              />
            </label>
            <div className="button-row">
              <button
                type="submit"
                disabled={!payoutRecipient || !payoutAmount}
              >
                Send Test Payout
              </button>
            </div>
          </form>

          {payoutError || payoutStatus ? (
            <div
              className={`status-strip ${payoutError ? "error" : "success"}`}
            >
              {payoutError || payoutStatus}
            </div>
          ) : null}

          {payoutDetails ? (
            <div className="detail-content" style={{ marginTop: "1rem" }}>
              <div className="detail-row">
                <span>Payout Batch ID</span>
                <strong>{payoutDetails.batchId}</strong>
              </div>
              <div className="detail-row">
                <span>Transaction ID</span>
                <strong>{payoutDetails.itemId}</strong>
              </div>
              <div className="detail-row">
                <span>Recipient</span>
                <strong>{payoutDetails.recipient}</strong>
              </div>
              <div className="detail-row">
                <span>Amount</span>
                <strong>
                  {payoutDetails.amount} {payoutDetails.currency}
                </strong>
              </div>
              <div className="detail-row">
                <span>Payout status</span>
                <strong>{payoutDetails.status}</strong>
              </div>
            </div>
          ) : null}
        </div>

        <div className="card panel balance-panel">
          <div className="panel-header">
            <h2>Seller Account Balance</h2>
            <div className="button-row">
              <span className="env-tag">
                {balance?.environment || config?.mode || "sandbox"}
              </span>
              <button
                className="secondary-button"
                onClick={refreshAccountBalance}
                disabled={isLoading}
              >
                Refresh balance
              </button>
            </div>
          </div>

          <p
            className="empty-state"
            style={{ marginTop: "0", marginBottom: "1rem" }}
          >
            Merchant/seller balance from the PayPal Reporting API. This is not
            the buyer wallet balance.
          </p>

          {isLoading ? (
            <p className="empty-state">Loading seller balance from PayPal…</p>
          ) : balanceError ? (
            <p className="error-message">{balanceError}</p>
          ) : balanceEntry ? (
            <div className="balance-list">
              <div className="balance-row">
                <span>Total Balance</span>
                <strong>{formatMoney(balanceEntry.total?.value || 0)}</strong>
              </div>
              <div className="balance-row">
                <span>Available Balance</span>
                <strong>
                  {formatMoney(balanceEntry.available?.value || 0)}
                </strong>
              </div>
              <div className="balance-row">
                <span>Withheld Balance</span>
                <strong>
                  {formatMoney(balanceEntry.withheld?.value || 0)}
                </strong>
              </div>
              <div className="balance-row">
                <span>Currency</span>
                <strong>{balanceEntry.currency}</strong>
              </div>
              <div className="balance-row">
                <span>Account Status</span>
                <strong>{balanceEntry.accountStatus || "ACTIVE"}</strong>
              </div>
              <div className="balance-row">
                <span>Account ID</span>
                <strong>{balanceEntry.accountId || "Not provided"}</strong>
              </div>
              <div className="balance-row">
                <span>Last Updated</span>
                <strong>
                  {balanceEntry.lastUpdated
                    ? new Date(balanceEntry.lastUpdated).toLocaleString()
                    : "Not provided"}
                </strong>
              </div>
            </div>
          ) : (
            <p className="empty-state">
              No seller account balance returned by PayPal.
            </p>
          )}
        </div>

        <div className="card panel balance-panel">
          <div className="panel-header">
            <h2>Buyer Payment Activity</h2>
          </div>

          <p
            className="empty-state"
            style={{ marginTop: "0", marginBottom: "1rem" }}
          >
            Actual payment captured from the buyer. This is the confirmed $1.00
            activity for the order.
          </p>

          {buyerPayment ? (
            <div className="balance-list">
              <div className="balance-row">
                <span>Amount Paid</span>
                <strong>{formatMoney(buyerPayment.amount || 0)}</strong>
              </div>
              <div className="balance-row">
                <span>Currency</span>
                <strong>{buyerPayment.currency || "USD"}</strong>
              </div>
              <div className="balance-row">
                <span>Capture ID</span>
                <strong>{buyerPayment.capture_id || "N/A"}</strong>
              </div>
              <div className="balance-row">
                <span>Transaction ID</span>
                <strong>{buyerPayment.transaction_id || "N/A"}</strong>
              </div>
              <div className="balance-row">
                <span>Payment Status</span>
                <strong>{buyerPayment.payment_status || "COMPLETED"}</strong>
              </div>
            </div>
          ) : (
            <p className="empty-state">
              No successful buyer payment captured yet.
            </p>
          )}
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

          {mlAnalytics ? (
            <div className="detail-content" style={{ marginTop: "1rem" }}>
              <div className="detail-row">
                <span>ML model</span>
                <strong>{mlAnalytics.model_type || "random_forest"}</strong>
              </div>
              <div className="detail-row">
                <span>Average risk</span>
                <strong>{mlAnalytics.summary?.average_risk_score ?? 0}</strong>
              </div>
              <div className="detail-row">
                <span>Low risk</span>
                <strong>{mlDistribution["LOW RISK"] ?? 0}</strong>
              </div>
              <div className="detail-row">
                <span>Medium risk</span>
                <strong>{mlDistribution["MEDIUM RISK"] ?? 0}</strong>
              </div>
              <div className="detail-row">
                <span>High risk</span>
                <strong>{mlDistribution["HIGH RISK"] ?? 0}</strong>
              </div>
              <div className="detail-row">
                <span>Model notes</span>
                <strong>
                  {mlAnalytics.training_data_source || "synthetic"}
                </strong>
              </div>
              <div className="detail-row">
                <span>Accuracy</span>
                <strong>{mlAnalytics.model_metrics?.accuracy ?? "n/a"}</strong>
              </div>
            </div>
          ) : null}
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
                <span>Transaction type</span>
                <strong>
                  {formatTransactionEventCode(
                    selectedTransaction.resource_type ||
                      selectedTransaction.transaction_type,
                  )}
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
