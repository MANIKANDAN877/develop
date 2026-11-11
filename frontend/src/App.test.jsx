import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import axios from "axios";
import App from "./App";

vi.mock("axios", () => ({
  default: {
    defaults: { withCredentials: true },
    get: vi.fn(),
    post: vi.fn(),
    patch: vi.fn(),
  },
}));

const API_URL = import.meta.env.VITE_API_URL || "http://localhost:8000";

const oldBalancePayload = {
  status: "ok",
  payload: {
    balances: [
      {
        currency: "USD",
        total_balance: { value: "5000.00", currency: "USD" },
        available_balance: { value: "5000.00", currency: "USD" },
        withheld_balance: { value: "0.00", currency: "USD" },
        last_updated: "2024-01-01T00:00:00Z",
      },
    ],
    currency: "USD",
    last_updated: "2024-01-01T00:00:00Z",
  },
};

const updatedBalancePayload = {
  status: "ok",
  payload: {
    balances: [
      {
        currency: "USD",
        total_balance: { value: "4999.00", currency: "USD" },
        available_balance: { value: "4999.00", currency: "USD" },
        withheld_balance: { value: "0.00", currency: "USD" },
        last_updated: "2024-01-02T00:00:00Z",
      },
    ],
    currency: "USD",
    last_updated: "2024-01-02T00:00:00Z",
  },
};

let balanceResponse = oldBalancePayload;

beforeEach(() => {
  window.open = vi.fn();
  window.history.pushState({}, "", "/");

  balanceResponse = oldBalancePayload;

  axios.get.mockImplementation((url) => {
    switch (url) {
      case `${API_URL}/api/paypal/config-status`:
        return Promise.resolve({ data: { mode: "sandbox" } });
      case `${API_URL}/api/paypal/transactions`:
        return Promise.resolve({ data: { results: [] } });
      case `${API_URL}/api/paypal/alerts`:
        return Promise.resolve({ data: { results: [] } });
      case `${API_URL}/api/paypal/webhook-events`:
        return Promise.resolve({ data: { results: [] } });
      case `${API_URL}/api/paypal/balance`:
        return Promise.resolve({ data: balanceResponse });
      case `${API_URL}/api/paypal/fraud/analytics`:
        return Promise.resolve({
          data: {
            summary: {
              risk_distribution: {
                "LOW RISK": 1,
                "MEDIUM RISK": 0,
                "HIGH RISK": 0,
              },
            },
          },
        });
      default:
        return Promise.reject(new Error(`Unhandled GET: ${url}`));
    }
  });

  axios.post.mockImplementation((url) => {
    switch (url) {
      case `${API_URL}/api/paypal/orders`:
        return Promise.resolve({
          data: {
            status: "ok",
            order_id: "ORDER-123",
            approval_url:
              "https://sandbox.paypal.com/checkoutnow?token=APPROVAL-123",
          },
        });
      case `${API_URL}/api/paypal/orders/ORDER-123/capture`:
      case `${API_URL}/api/paypal/orders/APPROVAL-123/capture`:
        balanceResponse = updatedBalancePayload;
        return Promise.resolve({
          data: {
            paypal_status: "COMPLETED",
            message: "Capture completed.",
            balance: updatedBalancePayload,
          },
        });
      default:
        return Promise.reject(new Error(`Unhandled POST: ${url}`));
    }
  });
});

afterEach(() => {
  vi.clearAllMocks();
});

test("shows sandbox funding status and a waiting message when the account is unfunded", async () => {
  balanceResponse = {
    status: "ok",
    payload: {
      account_id: "ACCT-123",
      account_status: "ACTIVE",
      balances: [
        {
          currency: "USD",
          total_balance: { value: "0.00", currency: "USD" },
          available_balance: { value: "0.00", currency: "USD" },
          withheld_balance: { value: "0.00", currency: "USD" },
          last_updated: "2024-01-03T00:00:00Z",
        },
      ],
      currency: "USD",
      last_updated: "2024-01-03T00:00:00Z",
    },
  };

  render(<App />);

  await waitFor(() => {
    expect(screen.getByText("Sandbox Funding Status")).toBeInTheDocument();
  });

  expect(screen.getByText("Business account status")).toBeInTheDocument();
  expect(screen.getAllByText("ACTIVE").length).toBeGreaterThan(0);
  expect(screen.getByText("UNFUNDED")).toBeInTheDocument();
  expect(
    screen.getByText(
      "Awaiting test payment to fund this sandbox business account.",
    ),
  ).toBeInTheDocument();
});

test("captures a PayPal order when the buyer returns from the approval URL", async () => {
  window.history.pushState({}, "", "/?token=APPROVAL-123");

  render(<App />);

  await waitFor(() => {
    expect(screen.getByText("Seller Account Balance")).toBeInTheDocument();
  });

  await waitFor(() => {
    expect(axios.post).toHaveBeenCalledWith(
      `${API_URL}/api/paypal/orders/APPROVAL-123/capture`,
      null,
      { withCredentials: true },
    );
  });

  await waitFor(() => {
    expect(screen.getByText("COMPLETED")).toBeInTheDocument();
  });
});

test("refreshes the displayed balance after a successful capture", async () => {
  const user = userEvent.setup();
  render(<App />);

  await waitFor(() => {
    expect(screen.getByText("Seller Account Balance")).toBeInTheDocument();
    expect(screen.getByText("Buyer Payment Activity")).toBeInTheDocument();
  });

  await waitFor(() => {
    expect(screen.getAllByText("$5,000.00").length).toBeGreaterThan(0);
  });

  await user.click(screen.getByRole("button", { name: "Create order" }));
  await user.click(
    screen.getByRole("button", { name: "Capture approved order" }),
  );

  await waitFor(() => {
    expect(screen.getAllByText("$4,999.00").length).toBeGreaterThan(0);
  });
  expect(screen.getByText("Buyer Payment Activity")).toBeInTheDocument();
  expect(screen.getByText("COMPLETED")).toBeInTheDocument();
});
