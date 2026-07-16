from sqlalchemy import (
    Boolean, Column, ForeignKey, Integer, String,
    Float, Date, DateTime, Text
)
from sqlalchemy.orm import relationship
from datetime import datetime
from database import Base


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(100), nullable=False)
    dob = Column(Date, nullable=False)

    # ── Auth ────────────────────────────────────────────────
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True)

    # ── MFA ─────────────────────────────────────────────────
    mfa_enabled = Column(Boolean, default=False)
    # Stored Fernet-encrypted; never in plaintext
    mfa_secret_encrypted = Column(Text, nullable=True)

    # ── Email Verification ───────────────────────────────────
    is_email_verified = Column(Boolean, default=False)
    email_otp_hash    = Column(String(128), nullable=True)   # bcrypt hash of 6-digit OTP
    email_otp_expiry  = Column(DateTime, nullable=True)

    # ── Password Reset ───────────────────────────────────────
    reset_otp_hash      = Column(String(128), nullable=True)  # bcrypt hash of OTP / TOTP token
    reset_otp_expiry    = Column(DateTime, nullable=True)
    reset_token         = Column(String(128), nullable=True)  # one-time reset token after verify
    reset_token_expiry  = Column(DateTime, nullable=True)

    # ── Brute-force protection ───────────────────────────────
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime, nullable=True)

    # ── Profile ──────────────────────────────────────────────
    monthly_income = Column(Float, default=0.0, nullable=False)

    # ── Timestamps ───────────────────────────────────────────
    created_at = Column(DateTime, default=datetime.utcnow)

    # ── Relationships ────────────────────────────────────────
    transactions  = relationship("Transaction",    back_populates="owner", cascade="all, delete-orphan")
    budgets       = relationship("Budget",         back_populates="owner", cascade="all, delete-orphan")
    savings_goals = relationship("SavingsGoal",   back_populates="owner", cascade="all, delete-orphan")
    import_logs   = relationship("BankImportLog", back_populates="owner", cascade="all, delete-orphan")
    linked_banks  = relationship("LinkedBank",    back_populates="owner", cascade="all, delete-orphan")


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(Integer, primary_key=True, index=True)
    amount = Column(Float, nullable=False)          # in Rupees (₹)
    category = Column(String(50), index=True, nullable=False)
    transaction_type = Column(String(10), nullable=False)   # 'Income' | 'Expense'
    description = Column(String(255), nullable=True)
    date = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    # ── Import tracking ──────────────────────────────────────
    # 'manual' | 'bank_csv' | 'bank_pdf' | 'bank_aa'
    import_source = Column(String(20), default="manual", nullable=False)
    # SHA-256(date|amount|description) — used for dedup on re-import
    import_hash = Column(String(64), nullable=True, index=True)

    # FK
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="transactions")


class Budget(Base):
    __tablename__ = "budgets"

    id = Column(Integer, primary_key=True, index=True)
    category = Column(String(50), nullable=False)
    monthly_limit = Column(Float, nullable=False)   # max spend in ₹
    month = Column(Integer, nullable=False)          # 1–12
    year = Column(Integer, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="budgets")


class SavingsGoal(Base):
    __tablename__ = "savings_goals"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(100), nullable=False)          # e.g. "Emergency Fund"
    target_amount = Column(Float, nullable=False)
    current_amount = Column(Float, default=0.0)
    deadline = Column(Date, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner = relationship("User", back_populates="savings_goals")


class BankImportLog(Base):
    """Audit record for every bank statement import."""
    __tablename__ = "bank_import_logs"

    id             = Column(Integer, primary_key=True, index=True)
    source         = Column(String(20), nullable=False)   # 'bank_csv' | 'bank_pdf' | 'bank_aa'
    bank_hint      = Column(String(50), nullable=True)    # detected/provided bank name
    rows_parsed    = Column(Integer, default=0)
    rows_imported  = Column(Integer, default=0)
    rows_skipped   = Column(Integer, default=0)   # bad data
    rows_duplicate = Column(Integer, default=0)   # dedup-blocked
    # SHA-256 of file bytes — proves we saw the file without storing it
    filename_hash  = Column(String(64), nullable=True)
    created_at     = Column(DateTime, default=datetime.utcnow)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner   = relationship("User", back_populates="import_logs")


class LinkedBank(Base):
    """
    Stores an encrypted bank adapter connection for a user.
    One active link per user (is_active=True).
    Credentials are NEVER stored — only the Fernet-encrypted token payload.
    """
    __tablename__ = "linked_banks"

    id              = Column(Integer, primary_key=True, index=True)
    adapter_type    = Column(String(20), nullable=False)    # 'mock' | 'obp' | 'setu'
    bank_label      = Column(String(100), nullable=True)    # Display name e.g. "HDFC Bank (Demo)"
    # Fernet-encrypted JSON containing the adapter's token/credentials
    encrypted_token = Column(Text, nullable=False)
    is_active       = Column(Boolean, default=True)
    linked_at       = Column(DateTime, default=datetime.utcnow)
    last_synced_at  = Column(DateTime, nullable=True)

    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    owner   = relationship("User", back_populates="linked_banks")