"""
FinAly AI — Banking Adapter
============================
Adapter pattern for open banking integration.

Current adapters:
  MockAdapter — Realistic Indian bank simulation (zero config, works offline)
  OBPAdapter  — Open Bank Project sandbox (free, openbanking.org.uk standard)

Upgrade path:
  To go live, implement SetuAdapter / PlaidAdapter and swap the class
  in get_banking_adapter() — zero frontend changes required.

Security:
  - No credentials flow to the frontend
  - All tokens stored Fernet-encrypted in DB (LinkedBank table)
  - Requests library used server-side only
"""

from __future__ import annotations
import hashlib, json, random
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Optional
import requests


# ══════════════════════════════════════════════════════════════
#  Data classes (plain dicts for SQLite-friendly serialisation)
# ══════════════════════════════════════════════════════════════

def _make_account(account_id: str, bank_name: str, acct_type: str,
                  balance: float, currency: str = "INR") -> dict:
    return {
        "account_id":   account_id,
        "bank_name":    bank_name,
        "account_type": acct_type,
        "balance":      round(balance, 2),
        "currency":     currency,
        "masked_number": "XXXX " + account_id[-4:],
    }


def _make_txn(txn_id: str, date: str, description: str, amount: float,
              txn_type: str, category: str, balance_after: float) -> dict:
    return {
        "txn_id":        txn_id,
        "date":          date,
        "description":   description,
        "amount":        round(abs(amount), 2),
        "type":          txn_type,          # "Income" | "Expense"
        "category":      category,
        "balance_after": round(balance_after, 2),
        "import_hash":   hashlib.sha256(
            f"{date}|{abs(amount):.2f}|{description}".encode()
        ).hexdigest(),
    }


# ══════════════════════════════════════════════════════════════
#  Abstract base
# ══════════════════════════════════════════════════════════════

class BankingAdapterBase(ABC):
    """All adapters must implement these three methods."""

    @abstractmethod
    def authenticate(self, credentials: dict) -> dict:
        """
        Validate credentials and return a token payload to encrypt+store.
        Raise ValueError with a user-facing message on failure.
        """

    @abstractmethod
    def get_accounts(self, token_payload: dict) -> list[dict]:
        """Return list of account dicts."""

    @abstractmethod
    def get_transactions(self, token_payload: dict, account_id: str,
                         days: int = 90) -> list[dict]:
        """Return list of transaction dicts for the given account."""

    @property
    @abstractmethod
    def adapter_name(self) -> str:
        """Short identifier, e.g. 'mock', 'obp', 'setu'."""


# ══════════════════════════════════════════════════════════════
#  Mock Adapter — Simulates HDFC / SBI-style Indian bank data
# ══════════════════════════════════════════════════════════════

class MockBankAdapter(BankingAdapterBase):
    """
    Fully self-contained mock.  No API keys, no network calls.
    Returns deterministic realistic Indian banking data so the demo
    works 100% offline and immediately.
    """

    adapter_name = "mock"

    # Realistic Indian transaction data
    _EXPENSE_TEMPLATES = [
        ("Swiggy Online Food Order",          "Food",          (150, 800)),
        ("Zomato Food Delivery",              "Food",          (120, 600)),
        ("IRCTC Rail Ticket",                 "Transport",     (450, 2500)),
        ("Uber Cab Booking",                  "Transport",     (80, 600)),
        ("Ola Cabs",                          "Transport",     (70, 450)),
        ("BESCOM Electricity Bill",           "Utilities",     (800, 3500)),
        ("Airtel Postpaid Bill",              "Utilities",     (299, 999)),
        ("Netflix Subscription",              "Entertainment", (149, 649)),
        ("Amazon Prime Subscription",         "Entertainment", (179, 1499)),
        ("BookMyShow Movie Tickets",          "Entertainment", (200, 800)),
        ("Decathlon Sports Equipment",        "Shopping",      (500, 5000)),
        ("Myntra Fashion Purchase",           "Shopping",      (400, 3000)),
        ("Flipkart Shopping",                 "Shopping",      (300, 8000)),
        ("Apollo Pharmacy",                   "Healthcare",    (200, 2000)),
        ("Fortis Hospital Consultation",      "Healthcare",    (500, 2500)),
        ("Bangalore Water Board",             "Utilities",     (300, 1200)),
        ("Coursera Online Course",            "Education",     (1500, 6000)),
        ("Udemy Course Purchase",             "Education",     (499, 2999)),
        ("Reliance Fresh Groceries",          "Food",          (400, 2000)),
        ("DMart Supermarket",                 "Food",          (500, 3000)),
        ("Petrol Bunk Shell",                 "Transport",     (500, 3000)),
        ("House Rent Transfer NEFT",          "Rent",          (8000, 25000)),
        ("Paytm Wallet Recharge",             "Other",         (200, 2000)),
        ("Google Pay UPI Transfer",           "Other",         (100, 5000)),
    ]

    _INCOME_TEMPLATES = [
        ("Salary Credit {company}",           (45000, 120000)),
        ("Freelance Payment NEFT",            (5000,  40000)),
        ("Interest Credit Savings A/C",       (200,   2000)),
        ("Dividend Credit Zerodha",           (1000,  15000)),
        ("Rental Income NEFT",               (8000,  30000)),
        ("Google Pay UPI Received",           (500,   10000)),
    ]

    _COMPANIES = ["Infosys Ltd", "TCS Ltd", "Wipro Ltd",
                  "HCL Technologies", "Accenture India"]

    def authenticate(self, credentials: dict) -> dict:
        """Mock: always succeeds. Credentials just stored as a demo marker."""
        return {
            "adapter":    "mock",
            "user_id":    credentials.get("username", "demo_user"),
            "mock_seed":  credentials.get("mock_seed", "finaly_demo"),
            "linked_at":  datetime.utcnow().isoformat(),
        }

    def get_accounts(self, token_payload: dict) -> list[dict]:
        seed = token_payload.get("mock_seed", "finaly_demo")
        rng  = random.Random(seed)
        return [
            _make_account(
                account_id  = f"HDFC{rng.randint(10000000, 99999999)}",
                bank_name   = "HDFC Bank",
                acct_type   = "Savings",
                balance     = round(rng.uniform(45000, 250000), 2),
            ),
            _make_account(
                account_id  = f"SBI{rng.randint(10000000, 99999999)}",
                bank_name   = "State Bank of India",
                acct_type   = "Current",
                balance     = round(rng.uniform(20000, 80000), 2),
            ),
        ]

    def get_transactions(self, token_payload: dict, account_id: str,
                         days: int = 90) -> list[dict]:
        seed = token_payload.get("mock_seed", "finaly_demo") + account_id
        rng  = random.Random(seed)
        today = datetime.utcnow()
        txns  = []
        balance = 120000.0

        company = rng.choice(self._COMPANIES)

        # 1 salary per month
        for month_offset in range(min(3, days // 30)):
            salary_date = today - timedelta(days=month_offset * 30 + rng.randint(0, 5))
            low, high   = self._INCOME_TEMPLATES[0][1]
            amount      = round(rng.uniform(low, high), 2)
            balance    += amount
            txns.append(_make_txn(
                txn_id      = f"SAL{salary_date.strftime('%Y%m%d')}{rng.randint(1000,9999)}",
                date        = salary_date.strftime("%Y-%m-%dT%H:%M:%S"),
                description = self._INCOME_TEMPLATES[0][0].format(company=company),
                amount      = amount,
                txn_type    = "Income",
                category    = "Income",
                balance_after = balance,
            ))

        # Random expenses over the period
        num_txns = rng.randint(25, 45)
        for _ in range(num_txns):
            desc, category, (low, high) = rng.choice(self._EXPENSE_TEMPLATES)
            amount  = round(rng.uniform(low, high), 2)
            balance = max(1000, balance - amount)
            days_ago = rng.randint(0, days)
            txn_date = today - timedelta(days=days_ago,
                                         hours=rng.randint(0, 23),
                                         minutes=rng.randint(0, 59))
            txns.append(_make_txn(
                txn_id      = f"TXN{txn_date.strftime('%Y%m%d')}{rng.randint(1000,9999)}",
                date        = txn_date.strftime("%Y-%m-%dT%H:%M:%S"),
                description = desc,
                amount      = amount,
                txn_type    = "Expense",
                category    = category,
                balance_after = balance,
            ))

        # Sort newest first
        txns.sort(key=lambda t: t["date"], reverse=True)
        return txns[:60]   # cap at 60 per account


# ══════════════════════════════════════════════════════════════
#  OBP Adapter — Open Bank Project sandbox (openbanking.org.uk)
# ══════════════════════════════════════════════════════════════

class OBPAdapter(BankingAdapterBase):
    """
    Open Bank Project v4 API adapter.
    Sandbox: https://apisandbox.openbankproject.com
    Auth:    Direct Login (username + password → GatewayLogin token)

    Free sandbox signup: https://apisandbox.openbankproject.com/user_mgt/sign_up
    """

    adapter_name = "obp"
    BASE_URL     = "https://apisandbox.openbankproject.com"
    API_VERSION  = "v4.0.0"
    CONSUMER_KEY = "vwfpvwfpvwfpvwfpvwfpvwfpvwfpvwfpvwfpvwfpvwfp"  # OBP public demo key

    def _api(self, path: str, token: Optional[str] = None,
             method: str = "GET", json_body: Optional[dict] = None) -> dict:
        url     = f"{self.BASE_URL}/obp/{self.API_VERSION}{path}"
        headers = {"Content-Type": "application/json"}
        if token:
            headers["Authorization"] = f"DirectLogin token={token}"

        try:
            resp = requests.request(method, url, headers=headers,
                                    json=json_body, timeout=10)
            resp.raise_for_status()
            return resp.json()
        except requests.exceptions.Timeout:
            raise ValueError("Banking API request timed out. Please try again.")
        except requests.exceptions.ConnectionError:
            raise ValueError("Cannot connect to OBP sandbox. Check network.")
        except requests.exceptions.HTTPError as e:
            try:
                detail = resp.json()
            except Exception:
                detail = {}
            msg = detail.get("message") or detail.get("error") or str(e)
            raise ValueError(f"OBP API error: {msg}")

    def authenticate(self, credentials: dict) -> dict:
        """
        OBP Direct Login.
        credentials = {"username": "...", "password": "...", "consumer_key": "..."}
        """
        username     = credentials.get("username", "").strip()
        password     = credentials.get("password", "").strip()
        consumer_key = credentials.get("consumer_key") or self.CONSUMER_KEY

        if not username or not password:
            raise ValueError("Username and password are required.")

        url     = f"{self.BASE_URL}/my/logins/direct"
        headers = {
            "Content-Type":  "application/json",
            "DirectLogin":   f'username="{username}",password="{password}",consumer_key="{consumer_key}"',
        }
        try:
            resp = requests.post(url, headers=headers, timeout=10)
            resp.raise_for_status()
            data  = resp.json()
            token = data.get("token", "")
            if not token:
                raise ValueError("OBP returned no token — check username/password.")
            return {
                "adapter":  "obp",
                "token":    token,
                "username": username,
                "linked_at": datetime.utcnow().isoformat(),
            }
        except requests.exceptions.Timeout:
            raise ValueError("OBP sandbox timed out. Try again.")
        except requests.exceptions.HTTPError:
            raise ValueError("OBP authentication failed — invalid credentials.")

    def get_accounts(self, token_payload: dict) -> list[dict]:
        token = token_payload.get("token", "")
        data  = self._api("/my/accounts", token=token)
        accounts = []
        for acct in data.get("accounts", []):
            bal = acct.get("balance", {})
            accounts.append(_make_account(
                account_id  = acct.get("id", ""),
                bank_name   = acct.get("bank_id", "OBP Bank"),
                acct_type   = acct.get("type", "Savings"),
                balance     = float(bal.get("amount", 0)),
                currency    = bal.get("currency", "EUR"),
            ))
        return accounts

    def get_transactions(self, token_payload: dict, account_id: str,
                         days: int = 90) -> list[dict]:
        token    = token_payload.get("token", "")
        bank_id  = token_payload.get("bank_id", "gh.29.uk")
        from_dt  = (datetime.utcnow() - timedelta(days=days)).strftime("%Y-%m-%dT00:00:00Z")
        path     = (f"/banks/{bank_id}/accounts/{account_id}"
                    f"/transactions?limit=60&sort_direction=DESC&from_date={from_dt}")
        data     = self._api(path, token=token)
        txns     = []
        for t in data.get("transactions", []):
            details = t.get("details", {})
            amount  = float(details.get("value", {}).get("amount", 0))
            txn_type = "Income" if amount > 0 else "Expense"
            desc     = details.get("description", "OBP Transaction")
            date_str = details.get("completed", datetime.utcnow().isoformat())[:19]
            txns.append(_make_txn(
                txn_id      = t.get("id", ""),
                date        = date_str,
                description = desc,
                amount      = abs(amount),
                txn_type    = txn_type,
                category    = _guess_category(desc),
                balance_after = float(t.get("balance", {}).get("amount", 0)),
            ))
        return txns


# ══════════════════════════════════════════════════════════════
#  Category guesser (used by OBP adapter for raw descriptions)
# ══════════════════════════════════════════════════════════════

_CATEGORY_RULES = {
    "Food":          ["food", "swiggy", "zomato", "restaurant", "cafe",
                      "grocery", "dmart", "reliance fresh", "bigbasket"],
    "Transport":     ["uber", "ola", "irctc", "petrol", "fuel", "metro",
                      "bus", "cab", "transport", "parking"],
    "Utilities":     ["electricity", "bescom", "water board", "airtel",
                      "jio", "bsnl", "broadband", "internet", "gas"],
    "Entertainment": ["netflix", "amazon prime", "spotify", "bookmyshow",
                      "hotstar", "zepto", "blinkit"],
    "Shopping":      ["amazon", "flipkart", "myntra", "ajio", "decathlon",
                      "shopping", "mall"],
    "Healthcare":    ["hospital", "pharmacy", "apollo", "fortis", "clinic",
                      "medical", "health"],
    "Education":     ["coursera", "udemy", "school", "college",
                      "fee", "course"],
    "Rent":          ["rent", "house", "flat", "pg", "hostel"],
    "Income":        ["salary", "credit", "refund", "cashback",
                      "dividend", "interest"],
}

def _guess_category(description: str) -> str:
    desc_lower = description.lower()
    for category, keywords in _CATEGORY_RULES.items():
        if any(kw in desc_lower for kw in keywords):
            return category
    return "Other"


# ══════════════════════════════════════════════════════════════
#  Factory
# ══════════════════════════════════════════════════════════════

_ADAPTERS: dict[str, BankingAdapterBase] = {
    "mock": MockBankAdapter(),
    "obp":  OBPAdapter(),
}

def get_banking_adapter(adapter_type: str = "mock") -> BankingAdapterBase:
    """Return the requested adapter. Defaults to mock for demo mode."""
    adapter = _ADAPTERS.get(adapter_type.lower())
    if not adapter:
        raise ValueError(
            f"Unknown adapter '{adapter_type}'. "
            f"Available: {list(_ADAPTERS.keys())}"
        )
    return adapter
