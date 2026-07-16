import re
from pydantic import BaseModel, EmailStr, Field, field_validator
from datetime import date, datetime
from typing import Optional, Literal


# ═══════════════════════════════════════════════════════════
#  Helpers
# ═══════════════════════════════════════════════════════════
def _validate_password_strength(v: str) -> str:
    """Enforce: 8+ chars, uppercase, lowercase, digit, special char."""
    if len(v) < 8:
        raise ValueError("Password must be at least 8 characters long.")
    if not re.search(r"[A-Z]", v):
        raise ValueError("Password must contain at least one uppercase letter.")
    if not re.search(r"[a-z]", v):
        raise ValueError("Password must contain at least one lowercase letter.")
    if not re.search(r"\d", v):
        raise ValueError("Password must contain at least one digit.")
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{};':\"\\|,.<>\/?]", v):
        raise ValueError("Password must contain at least one special character.")
    return v


# ═══════════════════════════════════════════════════════════
#  Auth Schemas
# ═══════════════════════════════════════════════════════════
class UserCreate(BaseModel):
    email: EmailStr
    full_name: str = Field(..., min_length=2, max_length=100,
                           pattern=r"^[a-zA-Z\s\-']+$")
    dob: date
    password: str = Field(..., min_length=8)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        return _validate_password_strength(v)

    @field_validator("dob")
    @classmethod
    def must_be_18(cls, v):
        today = date.today()
        age = today.year - v.year - ((today.month, today.day) < (v.month, v.day))
        if age < 18:
            raise ValueError("You must be at least 18 years old to register.")
        return v


class UserLogin(BaseModel):
    email: EmailStr
    password: str


class UserResponse(BaseModel):
    id: int
    email: EmailStr
    full_name: str
    dob: date
    is_active: bool
    mfa_enabled: bool
    created_at: datetime

    model_config = {"from_attributes": True}


class Token(BaseModel):
    access_token: str
    token_type: str
    mfa_required: bool = False
    full_name: str = ""
    email: str = ""


class RefreshRequest(BaseModel):
    refresh_token: str


# ═══════════════════════════════════════════════════════════
#  MFA Schemas
# ═══════════════════════════════════════════════════════════
class MFASetupResponse(BaseModel):
    totp_uri: str          # otpauth:// URI for QR code
    secret: str            # plaintext secret (shown once, never stored raw)
    qr_base64: Optional[str] = None  # base64 encoded PNG QR code


class MFAVerifyRequest(BaseModel):
    totp_code: str = Field(..., min_length=6, max_length=6, pattern=r"^\d{6}$")


class MFAVerifyResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ═══════════════════════════════════════════════════════════
#  Forgot Password Schemas
# ═══════════════════════════════════════════════════════════
class ForgotPasswordInitRequest(BaseModel):
    email: str = Field(..., description="User's registered email")

class ForgotPasswordInitResponse(BaseModel):
    method: str        # 'totp' | 'email_otp'
    email: str
    message: str
    smtp_available: bool = True

class ForgotPasswordVerifyRequest(BaseModel):
    email: str
    code: str = Field(..., min_length=6, max_length=6)  # 6-digit OTP or TOTP

class ForgotPasswordVerifyResponse(BaseModel):
    reset_token: str
    message: str

class ForgotPasswordResetRequest(BaseModel):
    email: str
    reset_token: str
    new_password: str = Field(..., min_length=8, max_length=128)


# ═══════════════════════════════════════════════════════════
#  Email Verification Schemas
# ═══════════════════════════════════════════════════════════
class SignupInitResponse(BaseModel):
    status: str        # 'otp_sent' | 'created' (fallback if no SMTP)
    email: str
    message: str

class EmailVerifyRequest(BaseModel):
    email: str
    otp: str = Field(..., min_length=6, max_length=6)

class EmailVerifyResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ═══════════════════════════════════════════════════════════
#  Transaction Schemas
# ═══════════════════════════════════════════════════════════
VALID_CATEGORIES = [
    "Food", "Rent", "Transport", "Utilities", "Healthcare",
    "Entertainment", "Shopping", "Education", "Income", "Other"
]

class TransactionCreate(BaseModel):
    amount: float = Field(..., gt=0)
    category: str
    transaction_type: Literal["Income", "Expense"]
    description: Optional[str] = Field(None, max_length=255)
    date: Optional[datetime] = None

    @field_validator("category")
    @classmethod
    def valid_category(cls, v):
        if v not in VALID_CATEGORIES:
            raise ValueError(f"Category must be one of: {VALID_CATEGORIES}")
        return v


class TransactionResponse(BaseModel):
    id: int
    amount: float
    category: str
    transaction_type: str
    description: Optional[str]
    date: datetime
    created_at: datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════
#  Budget Schemas
# ═══════════════════════════════════════════════════════════
class BudgetCreate(BaseModel):
    category: str
    monthly_limit: float = Field(..., gt=0)
    month: int = Field(..., ge=1, le=12)
    year: int = Field(..., ge=2020, le=2100)

    @field_validator("category")
    @classmethod
    def valid_category(cls, v):
        if v not in VALID_CATEGORIES:
            raise ValueError(f"Category must be one of: {VALID_CATEGORIES}")
        return v


class BudgetResponse(BaseModel):
    id: int
    category: str
    monthly_limit: float
    month: int
    year: int

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════
#  Savings Goal Schemas
# ═══════════════════════════════════════════════════════════
class SavingsGoalCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=100)
    target_amount: float = Field(..., gt=0)
    current_amount: float = Field(0.0, ge=0)
    deadline: Optional[date] = None


class SavingsGoalResponse(BaseModel):
    id: int
    name: str
    target_amount: float
    current_amount: float
    deadline: Optional[date]
    created_at: datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════
#  Profile Schemas
# ═══════════════════════════════════════════════════════════
class MonthlyIncomeUpdate(BaseModel):
    monthly_income: float = Field(..., ge=0)


# ═══════════════════════════════════════════════════════════
#  Dashboard Summary Schema
# ═══════════════════════════════════════════════════════════
class DashboardSummary(BaseModel):
    full_name: str = ""
    email: str = ""
    total_balance: float
    monthly_income: float
    monthly_expenses: float
    savings_progress_pct: float
    recent_transactions: list[TransactionResponse]
    category_breakdown: dict[str, float]
    weekly_expenses: list[float]   # 4 weeks of expenses for bar chart
    daily_expenses: list[float]    # 7 days (Mon-Sun) of expenses
    monthly_expense_totals: list[float]  # 6 months of expenses
    ai_insights: list[dict] = []


# ═══════════════════════════════════════════════════════════
#  Bank Import Schemas
# ═══════════════════════════════════════════════════════════

class BankPreviewRow(BaseModel):
    """One parsed transaction row — not yet saved to DB."""
    date: str                    # ISO 8601 datetime string
    description: str
    amount: float = Field(..., gt=0)
    transaction_type: Literal["Income", "Expense"]
    category: str
    confidence: str              # 'high' | 'low'
    import_hash: str             # SHA-256 dedup key


class BankPreviewResponse(BaseModel):
    """Returned by POST /api/bank/upload — preview before confirming import."""
    bank_detected: str
    source: str                  # 'bank_csv' | 'bank_pdf'
    rows: list[BankPreviewRow]
    total_rows: int
    parse_errors: list[str]


class BankImportRowRequest(BaseModel):
    """A single row the user has selected to import."""
    date: str
    description: str = Field(..., max_length=255)
    amount: float = Field(..., gt=0)
    transaction_type: Literal["Income", "Expense"]
    category: str
    import_hash: str = Field(..., min_length=64, max_length=64)


class BankImportRequest(BaseModel):
    """Payload for POST /api/bank/import — user-confirmed rows."""
    rows: list[BankImportRowRequest] = Field(..., max_length=500)
    bank: str = "unknown"
    source: str = "bank_csv"


class BankImportResponse(BaseModel):
    """Result of a completed import."""
    imported:          int
    skipped_duplicate: int
    skipped_invalid:   int
    total_selected:    int


class BankImportLogResponse(BaseModel):
    """One entry in the import history."""
    id:             int
    source:         str
    bank_hint:      Optional[str]
    rows_parsed:    int
    rows_imported:  int
    rows_skipped:   int
    rows_duplicate: int
    created_at:     datetime

    model_config = {"from_attributes": True}


# ═══════════════════════════════════════════════════════════
#  Live Banking Adapter Schemas
# ═══════════════════════════════════════════════════════════

class BankConnectRequest(BaseModel):
    """POST /api/bank/connect — link a bank via adapter."""
    adapter: Literal["mock", "obp"] = "mock"
    # For mock: any username works (no auth)
    # For obp:  username + password for OBP sandbox account
    username: Optional[str] = None
    password: Optional[str] = None
    consumer_key: Optional[str] = None    # OBP consumer key (optional, uses public demo key)
    mock_seed: Optional[str] = None       # deterministic seed for mock data


class BankAccountOut(BaseModel):
    """A single bank account returned by the adapter."""
    account_id:   str
    bank_name:    str
    account_type: str
    balance:      float
    currency:     str
    masked_number: str


class BankTransactionOut(BaseModel):
    """A single transaction returned by the adapter."""
    txn_id:       str
    date:         str
    description:  str
    amount:       float
    type:         str          # "Income" | "Expense"
    category:     str
    balance_after: float
    import_hash:  str


class BankStatusOut(BaseModel):
    """GET /api/bank/status response."""
    linked:        bool
    adapter:       Optional[str] = None
    bank_label:    Optional[str] = None
    linked_at:     Optional[str] = None
    last_synced_at: Optional[str] = None


class BankConnectOut(BaseModel):
    """POST /api/bank/connect response."""
    success:    bool
    adapter:    str
    bank_label: str
    message:    str


class BankImportFromAdapterRequest(BaseModel):
    """POST /api/bank/import-live — import transactions fetched from adapter."""
    account_id: str
    days: int = Field(default=90, ge=1, le=365)