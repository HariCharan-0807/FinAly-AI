"""
FinAly AI — FastAPI Backend
Ultimate Secure Version | GeoNixa Internship Project
"""

import hashlib
import io
from datetime import datetime, timezone, date as _date
from typing import Optional
from collections import defaultdict

from pydantic import BaseModel as _PydanticBase
from fastapi import (
    FastAPI, Depends, HTTPException, Request, status,
    Header, File, UploadFile, Form
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session
from sqlalchemy import text as _sql_text
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

import models
import schemas
from bank_parser import parse_statement
from banking_adapter import get_banking_adapter
from database import engine, get_db
from security import (
    get_password_hash, verify_password,
    generate_totp_secret, get_totp_uri, verify_totp, get_totp_qr_base64,
    encrypt_secret, decrypt_secret
)
from auth import (
    create_access_token, create_refresh_token,
    decode_access_token, decode_refresh_token, blacklist_token
)
from config import MAX_LOGIN_ATTEMPTS, LOCKOUT_MINUTES

# ═══════════════════════════════════════════════════════════
#  Bootstrap + DB Migrations
# ═══════════════════════════════════════════════════════════
try:
    models.Base.metadata.create_all(bind=engine)
except Exception as e:
    print(f"[Startup] Notice creating tables: {e}")


def _run_db_migrations() -> None:
    """
    Zero-downtime SQLite migrations.
    Adds new columns to existing tables without wiping data.
    create_all() only creates missing tables, not missing columns.
    """
    migrations = [
        "ALTER TABLE transactions ADD COLUMN import_source VARCHAR(20) DEFAULT 'manual'",
        "ALTER TABLE transactions ADD COLUMN import_hash  VARCHAR(64)",
        # Email verification columns
        "ALTER TABLE users ADD COLUMN is_email_verified BOOLEAN DEFAULT 1",
        "ALTER TABLE users ADD COLUMN email_otp_hash VARCHAR(128)",
        "ALTER TABLE users ADD COLUMN email_otp_expiry DATETIME",
        # Password reset columns
        "ALTER TABLE users ADD COLUMN reset_otp_hash VARCHAR(128)",
        "ALTER TABLE users ADD COLUMN reset_otp_expiry DATETIME",
        "ALTER TABLE users ADD COLUMN reset_token VARCHAR(128)",
        "ALTER TABLE users ADD COLUMN reset_token_expiry DATETIME",
    ]
    try:
        with engine.connect() as conn:
            for stmt in migrations:
                try:
                    conn.execute(_sql_text(stmt))
                    conn.commit()
                except Exception:
                    pass  # Column already exists — safe to ignore
    except Exception as e:
        print(f"[Startup] Notice running migrations: {e}")


_run_db_migrations()

limiter = Limiter(key_func=get_remote_address)

app = FastAPI(
    title="FinAly AI API",
    description="AI-Powered Personal Finance Assistant — Secure Backend",
    version="2.0.0",
    docs_url="/api/docs",
    redoc_url=None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# ── Public health check (no auth needed) ───────────────────
@app.get("/api/healthz")
def health_check(db: Session = Depends(get_db)):
    from ml_engine import run_classical_ml_analytics
    try:
        # Get first user's ML data for quick sanity check
        first_user = db.query(models.User).first()
        if first_user:
            ml = run_classical_ml_analytics(db, first_user.id)
        else:
            ml = {"model_status": "no_users_yet"}
    except Exception as e:
        ml = {"error": str(e)}
    return {"status": "ok", "smtp_enabled": __import__('config').SMTP_ENABLED, "smtp_from": __import__('config').SMTP_FROM or "NOT SET", "ml": ml}


# ── Email debug endpoint (remove after debugging) ────────────
@app.get("/api/debug/smtp-test")
def smtp_test(to: str = ""):
    """Test email sending via Gmail API."""
    from config import EMAIL_ENABLED, GMAIL_FROM
    from email_service import send_otp_email
    if not to:
        to = "test@example.com"
    if not EMAIL_ENABLED:
        return {"error": "Gmail API not configured. Run setup_gmail.py and add variables to Railway.",
                "EMAIL_ENABLED": False}
    try:
        sent = send_otp_email(to, "123456", purpose="verification")
        return {"success": sent, "provider": "gmail_api", "from": GMAIL_FROM, "to": to}
    except Exception as e:
        return {"error": str(e)}



# ═══════════════════════════════════════════════════════════
#  Security Headers Middleware
# ═══════════════════════════════════════════════════════════
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; "
        "font-src 'self' https://fonts.gstatic.com; "
        "img-src 'self' data: https://api.qrserver.com; "
        "connect-src 'self' http://127.0.0.1:8000 http://localhost:8000 https://*.railway.app https://*.vercel.app;"
    )
    return response


# ═══════════════════════════════════════════════════════════
#  CORS
# ═══════════════════════════════════════════════════════════
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://web-production-c2931.up.railway.app",
        "https://3-deploy-backend-to-railway-production.up.railway.app",
        # VS Code Live Server
        "http://127.0.0.1:5500", "http://localhost:5500",
        # Common dev servers (Vite, CRA, ng serve, etc.)
        "http://127.0.0.1:3000", "http://localhost:3000",
        "http://127.0.0.1:5173", "http://localhost:5173",
        "http://127.0.0.1:4200", "http://localhost:4200",
        "http://127.0.0.1:8080", "http://localhost:8080",
        "http://127.0.0.1:4000", "http://localhost:4000",
        # file:// protocol (null origin) — for direct file opening
        "null",
    ],
    allow_origin_regex=r"https://.*\.railway\.app|https://.*\.vercel\.app",
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE"],
    allow_headers=["Authorization", "Content-Type"],
)


# ═══════════════════════════════════════════════════════════
#  Auth Dependency — validates JWT on protected routes
# ═══════════════════════════════════════════════════════════
def get_current_user(
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db)
) -> models.User:
    credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    if not authorization or not authorization.startswith("Bearer "):
        raise credentials_exc

    token = authorization.split(" ", 1)[1]
    payload = decode_access_token(token)
    if payload is None:
        raise credentials_exc

    email: str = payload.get("sub")
    if not email:
        raise credentials_exc

    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_active:
        raise credentials_exc
    return user


# ═══════════════════════════════════════════════════════════
#  Endpoint: Health Check
# ═══════════════════════════════════════════════════════════
@app.get("/api/health")
def health():
    return {"status": "ok", "service": "FinAly AI API v2"}


# ═══════════════════════════════════════════════════════════
#  Endpoint: Sign Up (with email OTP verification)
# ═══════════════════════════════════════════════════════════
@app.post("/api/signup", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def create_user(request: Request, user: schemas.UserCreate, db: Session = Depends(get_db)):
    from email_service import send_otp_email, generate_otp
    from config import EMAIL_ENABLED, OTP_EXPIRE_MINUTES
    from datetime import timedelta

    if db.query(models.User).filter(models.User.email == user.email).first():
        raise HTTPException(status_code=400, detail="An account with this email already exists.")

    new_user = models.User(
        email=user.email,
        full_name=user.full_name,
        dob=user.dob,
        hashed_password=get_password_hash(user.password),
        is_email_verified=not EMAIL_ENABLED,  # auto-verify if no email configured
    )

    if EMAIL_ENABLED:
        # Generate OTP and send verification email
        otp = generate_otp()
        new_user.email_otp_hash   = get_password_hash(otp)
        new_user.email_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
        db.add(new_user)
        db.commit()
        sent = send_otp_email(user.email, otp, purpose="verification")
        print(f"[Signup] Verification OTP to {user.email}: {'SUCCESS' if sent else 'FAILED'}")
        if not sent:
            # If email failed, auto-verify so user isn't locked out
            new_user.is_email_verified = True
            db.commit()
        return {"status": "otp_sent" if sent else "created", "email": user.email,
                "message": f"A verification code was sent to {user.email}. Enter it to activate your account." if sent else "Account created successfully."}
    else:
        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return {"status": "created", "email": user.email,
                "message": "Account created successfully. You can now log in."}


# ═══════════════════════════════════════════════════════════
#  Endpoint: Verify Email OTP (after signup)
# ═══════════════════════════════════════════════════════════
@app.post("/api/auth/verify-email")
@limiter.limit("10/minute")
def verify_email(request: Request, body: schemas.EmailVerifyRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == body.email).first()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid email address.")
    if user.is_email_verified:
        raise HTTPException(status_code=400, detail="Email already verified. Please log in.")
    if not user.email_otp_hash or not user.email_otp_expiry:
        raise HTTPException(status_code=400, detail="No verification code found. Please sign up again.")
    if datetime.now(timezone.utc) > user.email_otp_expiry.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=400, detail="Verification code expired. Please sign up again.")
    if not verify_password(body.otp, user.email_otp_hash):
        raise HTTPException(status_code=400, detail="Invalid verification code.")

    # Activate account
    user.is_email_verified = True
    user.email_otp_hash    = None
    user.email_otp_expiry  = None
    db.commit()

    # Send welcome email (non-blocking)
    try:
        from email_service import send_welcome_email
        send_welcome_email(user.email, user.full_name)
    except Exception:
        pass

    # Issue tokens so user is immediately logged in
    if user.mfa_enabled:
        pre_token = create_access_token({"sub": str(user.id), "pre_mfa": True}, expires_delta=__import__('datetime').timedelta(minutes=5))
        return {"status": "mfa_required", "token": pre_token}

    access_token  = create_access_token({"sub": str(user.id)})
    refresh_token = create_refresh_token({"sub": str(user.id)})
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "full_name": user.full_name or "",
        "email": user.email or "",
    }


# ═══════════════════════════════════════════════════════════
#  Endpoint: Forgot Password — Step 1: Init (email OTP only)
# ═══════════════════════════════════════════════════════════
@app.post("/api/auth/forgot-password/init")
@limiter.limit("5/minute")
def forgot_password_init(request: Request, body: schemas.ForgotPasswordInitRequest, db: Session = Depends(get_db)):
    from email_service import send_otp_email, generate_otp
    from config import EMAIL_ENABLED, OTP_EXPIRE_MINUTES
    from datetime import timedelta

    if not EMAIL_ENABLED:
        raise HTTPException(
            status_code=503,
            detail="Email service is not configured on this server. Please contact support."
        )

    user = db.query(models.User).filter(models.User.email == body.email).first()
    if user:
        otp = generate_otp()
        user.reset_otp_hash   = get_password_hash(otp)
        user.reset_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
        db.commit()
        sent = send_otp_email(body.email, otp, purpose="password_reset")
        print(f"[ForgotPwd] OTP send to {body.email}: {'SUCCESS' if sent else 'FAILED'}")
    else:
        print(f"[ForgotPwd] No user found for {body.email} — returning generic message")

    # Always return same response — don't reveal if email exists
    return {"message": f"If {body.email} is registered, a reset code has been sent."}


# ═══════════════════════════════════════════════════════════
#  Endpoint: Forgot Password — Step 2: Verify Email OTP
# ═══════════════════════════════════════════════════════════
@app.post("/api/auth/forgot-password/verify")
@limiter.limit("10/minute")
def forgot_password_verify(request: Request, body: schemas.ForgotPasswordVerifyRequest, db: Session = Depends(get_db)):
    import secrets
    from config import RESET_TOKEN_EXPIRE_MINUTES
    from datetime import timedelta

    user = db.query(models.User).filter(models.User.email == body.email).first()
    if not user or not user.reset_otp_hash or not user.reset_otp_expiry:
        raise HTTPException(status_code=400, detail="Invalid or expired reset code. Please request a new one.")

    if datetime.now(timezone.utc) > user.reset_otp_expiry.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=400, detail="Reset code has expired. Please request a new one.")

    if not verify_password(body.code, user.reset_otp_hash):
        raise HTTPException(status_code=400, detail="Incorrect reset code. Please check your email and try again.")

    # Issue a one-time reset token valid for 10 minutes
    reset_token = secrets.token_urlsafe(32)
    user.reset_token        = get_password_hash(reset_token)
    user.reset_token_expiry = datetime.now(timezone.utc) + timedelta(minutes=RESET_TOKEN_EXPIRE_MINUTES)
    user.reset_otp_hash     = None
    user.reset_otp_expiry   = None
    db.commit()

    return {"reset_token": reset_token, "message": "Code verified. You can now set a new password."}


# ═══════════════════════════════════════════════════════════
#  Endpoint: Forgot Password — Step 3: Reset Password
# ═══════════════════════════════════════════════════════════
@app.post("/api/auth/forgot-password/reset")
@limiter.limit("5/minute")
def forgot_password_reset(request: Request, body: schemas.ForgotPasswordResetRequest, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == body.email).first()
    if not user or not user.reset_token or not user.reset_token_expiry:
        raise HTTPException(status_code=400, detail="Invalid or expired reset session. Please start over.")
    if datetime.now(timezone.utc) > user.reset_token_expiry.replace(tzinfo=timezone.utc):
        raise HTTPException(status_code=400, detail="Reset session expired. Please start over.")
    if not verify_password(body.reset_token, user.reset_token):
        raise HTTPException(status_code=400, detail="Invalid reset token.")

    # Update password and clear reset fields
    user.hashed_password    = get_password_hash(body.new_password)
    user.reset_token        = None
    user.reset_token_expiry = None
    user.failed_login_attempts = 0
    user.lockout_until = None
    db.commit()

    return {"message": "Password reset successfully. You can now log in."}




# ═══════════════════════════════════════════════════════════
#  Endpoint: Log In  (issues a *pre-MFA* access token)
# ═══════════════════════════════════════════════════════════
@app.post("/api/login", response_model=schemas.Token)
@limiter.limit("20/minute")
def login(request: Request, credentials: schemas.UserLogin, db: Session = Depends(get_db)):
    user = db.query(models.User).filter(models.User.email == credentials.email).first()

    # Account lockout check
    if user and user.lockout_until:
        if datetime.now(timezone.utc) < user.lockout_until.replace(tzinfo=timezone.utc):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Account locked due to too many failed attempts. Try again in {LOCKOUT_MINUTES} minutes."
            )
        else:
            # Lockout expired — reset
            user.failed_login_attempts = 0
            user.lockout_until = None
            db.commit()

    # Ambiguous error — never reveal whether email or password was wrong
    if not user or not verify_password(credentials.password, user.hashed_password):
        if user:
            user.failed_login_attempts += 1
            if user.failed_login_attempts >= MAX_LOGIN_ATTEMPTS:
                from datetime import timedelta
                user.lockout_until = datetime.now(timezone.utc) + timedelta(minutes=LOCKOUT_MINUTES)
            db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Block login if email not verified — resend OTP
    if not user.is_email_verified:
        from config import EMAIL_ENABLED, OTP_EXPIRE_MINUTES
        if EMAIL_ENABLED:
            from email_service import send_otp_email, generate_otp
            from datetime import timedelta
            otp = generate_otp()
            user.email_otp_hash   = get_password_hash(otp)
            user.email_otp_expiry = datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES)
            db.commit()
            send_otp_email(user.email, otp, purpose="verification")
        raise HTTPException(
            status_code=403,
            detail="email_not_verified"
        )

    # Successful login — reset failed attempts
    user.failed_login_attempts = 0
    user.lockout_until = None
    db.commit()

    # Issue a short-lived access token; frontend will use it to hit /api/mfa/verify
    access_token = create_access_token(data={"sub": user.email, "mfa_pending": True})

    return {
        "access_token": access_token,
        "token_type": "bearer",
        "mfa_required": user.mfa_enabled,
        "full_name": user.full_name or "",
        "email": user.email or "",
    }


# ═══════════════════════════════════════════════════════════
#  Endpoint: MFA Setup  (generate QR code for first-time setup)
# ═══════════════════════════════════════════════════════════
@app.post("/api/mfa/setup", response_model=schemas.MFASetupResponse)
def mfa_setup(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if current_user.mfa_enabled:
        raise HTTPException(status_code=400, detail="MFA is already enabled on this account.")

    #  REUSE existing secret if one was already generated.
    # This ensures the QR code stays consistent even if the user refreshes
    # the page or calls this endpoint multiple times before verifying.
    if current_user.mfa_secret_encrypted:
        secret = decrypt_secret(current_user.mfa_secret_encrypted)
    else:
        secret = generate_totp_secret()
        current_user.mfa_secret_encrypted = encrypt_secret(secret)
        db.commit()

    uri = get_totp_uri(secret, current_user.email)
    qr_b64 = get_totp_qr_base64(uri)
    return {"totp_uri": uri, "secret": secret, "qr_base64": f"data:image/png;base64,{qr_b64}"}


# ═══════════════════════════════════════════════════════════
#  Endpoint: MFA Verify  (confirm OTP → issue full tokens)
# ═══════════════════════════════════════════════════════════
@app.post("/api/mfa/verify", response_model=schemas.MFAVerifyResponse)
def mfa_verify(
    body: schemas.MFAVerifyRequest,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    if not current_user.mfa_secret_encrypted:
        raise HTTPException(status_code=400, detail="MFA has not been set up for this account.")

    plain_secret = decrypt_secret(current_user.mfa_secret_encrypted)
    if not verify_totp(plain_secret, body.totp_code):
        raise HTTPException(status_code=400, detail="Invalid or expired OTP code.")

    # Enable MFA on first successful verification
    if not current_user.mfa_enabled:
        current_user.mfa_enabled = True
        db.commit()

    access_token = create_access_token(data={"sub": current_user.email})
    refresh_token = create_refresh_token(data={"sub": current_user.email})

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer",
        "full_name": current_user.full_name or "",
        "email": current_user.email or "",
    }


# ═══════════════════════════════════════════════════════════
#  Endpoint: Refresh Token
# ═══════════════════════════════════════════════════════════
@app.post("/api/token/refresh")
def refresh_token(body: schemas.RefreshRequest, db: Session = Depends(get_db)):
    payload = decode_refresh_token(body.refresh_token)
    if payload is None:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    email = payload.get("sub")
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found.")

    blacklist_token(body.refresh_token)   # rotate — old refresh token is now void
    new_access = create_access_token(data={"sub": user.email})
    new_refresh = create_refresh_token(data={"sub": user.email})

    return {
        "access_token": new_access,
        "refresh_token": new_refresh,
        "token_type": "bearer",
        "full_name": user.full_name or "",
        "email": user.email or "",
    }


# ═══════════════════════════════════════════════════════════
#  Endpoint: Logout
# ═══════════════════════════════════════════════════════════
@app.post("/api/logout")
def logout(
    authorization: Optional[str] = Header(None),
    current_user: models.User = Depends(get_current_user)
):
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split(" ", 1)[1]
        blacklist_token(token)
    return {"message": "Successfully logged out."}


# ═══════════════════════════════════════════════════════════
#  Endpoint: Machine Learning Predictive Analytics
# ═══════════════════════════════════════════════════════════
@app.get("/api/ml/insights")
def machine_learning_insights(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Run Ordinary Least Squares (OLS) forecasting & Z-score anomaly detection."""
    from ml_engine import run_classical_ml_analytics
    return run_classical_ml_analytics(db, current_user.id)


# ═══════════════════════════════════════════════════════════
#  Endpoint: Dashboard Summary
# ═══════════════════════════════════════════════════════════
@app.get("/api/dashboard/summary", response_model=schemas.DashboardSummary)
def dashboard_summary(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    from datetime import timedelta
    import calendar

    now = datetime.now(timezone.utc)
    txns = db.query(models.Transaction).filter(
        models.Transaction.user_id == current_user.id
    ).all()

    monthly_txns = [
        t for t in txns
        if t.date.month == now.month and t.date.year == now.year
    ]

    # Monthly income comes from the user's profile, not summed transactions
    monthly_income = current_user.monthly_income or 0.0
    monthly_expenses = sum(t.amount for t in monthly_txns if t.transaction_type == "Expense")

    # Total balance = fixed income - total expenses (all time)
    total_income_all = sum(t.amount for t in txns if t.transaction_type == "Income")
    total_expenses_all = sum(t.amount for t in txns if t.transaction_type == "Expense")
    total_balance = total_income_all - total_expenses_all

    # Savings progress = sum of (current_amount / target_amount) across goals
    goals = db.query(models.SavingsGoal).filter(
        models.SavingsGoal.user_id == current_user.id
    ).all()
    if goals:
        progress = sum(
            min(g.current_amount / g.target_amount, 1.0) for g in goals
        ) / len(goals) * 100
    else:
        progress = 0.0

    # Category breakdown (expenses only, current month)
    breakdown: dict[str, float] = defaultdict(float)
    for t in monthly_txns:
        if t.transaction_type == "Expense":
            breakdown[t.category] += t.amount

    recent = sorted(txns, key=lambda t: t.date, reverse=True)[:10]

    # ── Populate chart data from real transactions ──
    # ── Weekly expenses (4 weeks of current month) ──
    weekly_expenses = [0.0, 0.0, 0.0, 0.0]
    for t in monthly_txns:
        if t.transaction_type == "Expense":
            day = t.date.day
            week_idx = min((day - 1) // 7, 3)  # 0-3
            weekly_expenses[week_idx] += t.amount

    # ── Daily expenses (Mon=0 to Sun=6, current week) ──
    daily_expenses = [0.0] * 7
    # Start of current week (Monday 00:00 UTC)
    start_of_week = now - timedelta(days=now.weekday())
    start_of_week = start_of_week.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_week = start_of_week + timedelta(days=7)
    for t in txns:
        if t.transaction_type == "Expense":
            # Make t.date timezone-aware for comparison
            t_date = t.date.replace(tzinfo=timezone.utc) if t.date.tzinfo is None else t.date
            if start_of_week <= t_date < end_of_week:
                day_idx = t_date.weekday()  # 0=Mon, 6=Sun
                daily_expenses[day_idx] += t.amount

    # ── Monthly expense totals (last 6 months) ──
    monthly_expense_totals = [0.0] * 6
    month_labels = []
    for i in range(5, -1, -1):
        m = now.month - i
        y = now.year
        while m <= 0:
            m += 12
            y -= 1
        month_labels.append((y, m))

    for idx, (y, m) in enumerate(month_labels):
        for t in txns:
            if t.transaction_type == "Expense" and t.date.month == m and t.date.year == y:
                monthly_expense_totals[idx] += t.amount

    # ── Dynamic AI Savings Insights ──
    all_expenses = [t for t in txns if t.transaction_type == "Expense"]
    total_expense_all = sum(t.amount for t in all_expenses)
    ai_insights = []

    if total_expense_all == 0:
        ai_insights = [
            {
                "title": "Unlock AI Spend Analysis",
                "text": "Add your first expense transaction or connect your bank account to receive personalized recommendations based on your spending habits.",
                "highlight": False
            },
            {
                "title": "Set Your Monthly Income",
                "text": "Define your monthly income in your profile so our AI can calculate your exact disposable cash flow and optimal budget thresholds.",
                "highlight": True
            },
            {
                "title": "Create Your 50/30/20 Plan",
                "text": "Aim to allocate 50% of income for essentials, 30% for personal wants, and 20% for savings once your transactions begin tracking.",
                "highlight": False
            }
        ]
    else:
        # Use current month breakdown if available, else all time breakdown
        active_breakdown = dict(breakdown) if sum(breakdown.values()) > 0 else defaultdict(float)
        if not active_breakdown:
            for t in all_expenses:
                active_breakdown[t.category] += t.amount
        sorted_cats = sorted(active_breakdown.items(), key=lambda x: x[1], reverse=True)
        total_spent_active = sum(active_breakdown.values())

        # Card 1: Top Category Optimization
        top_cat, top_amt = sorted_cats[0]
        pct_of_total = round((top_amt / total_spent_active) * 100, 1) if total_spent_active > 0 else 0
        save_15 = round(top_amt * 0.15, 2)
        if top_cat in ["Food & Dining", "Food", "Dining out", "Restaurants", "Entertainment", "Shopping"]:
            c1_title = f"Optimize {top_cat} Outflows"
            c1_text = f"{top_cat} is your largest expense at ₹{top_amt:,.2f} ({pct_of_total}% of total spend). Trimming this by just 15% retains ₹{save_15:,.2f}/month in your bank account."
        elif top_cat in ["Rent", "Housing", "Utilities", "Bills"]:
            c1_title = f"Audit Fixed {top_cat} Costs"
            c1_text = f"{top_cat} accounts for ₹{top_amt:,.2f} ({pct_of_total}% of spend). Check for unused subscriptions or energy leaks to reduce fixed monthly burn."
        else:
            c1_title = f"Trim {top_cat} Expenses"
            c1_text = f"You spent ₹{top_amt:,.2f} on {top_cat} ({pct_of_total}% of outflows). Setting a weekly cap of ₹{round((top_amt * 0.85)/4, 2):,.2f} could save you ₹{save_15:,.2f}/month."
        ai_insights.append({"title": c1_title, "text": c1_text, "highlight": False})

        # Card 2: Savings Rate / SIP Strategy
        if monthly_income > 0 and total_spent_active > 0:
            savings_rate = ((monthly_income - total_spent_active) / monthly_income) * 100
            if savings_rate < 20:
                shortfall = round((0.20 * monthly_income) - (monthly_income - total_spent_active), 2)
                c2_title = "Bridge Your Savings Gap"
                c2_text = f"Your current savings margin is {max(0, round(savings_rate, 1))}%. Reducing monthly expenses by ₹{max(0, shortfall):,.2f} brings you to the ideal 20% financial wellness mark."
            else:
                invest_amt = round((monthly_income - total_spent_active) * 0.50, 2)
                c2_title = "Put Your Surplus to Work"
                c2_text = f"Excellent {round(savings_rate, 1)}% savings rate! Investing ₹{max(500, invest_amt):,.2f}/month into an index fund SIP at 12% p.a. can double your money in ~6 years."
            ai_insights.append({"title": c2_title, "text": c2_text, "highlight": True})
        else:
            potential_sip = max(1000, round(total_spent_active * 0.10, -2))
            ai_insights.append({
                "title": "Start a Monthly SIP",
                "text": f"Setting aside just ₹{potential_sip:,.2f}/month into a mutual fund SIP at 12% annual return builds over ₹{round(potential_sip * 12 * 5 * 1.35, -3):,.0f} in 5 years through compounding.",
                "highlight": True
            })

        # Card 3: Second Category or Automation
        if len(sorted_cats) >= 2:
            cat2_name, cat2_amt = sorted_cats[1]
            save_cat2 = round(cat2_amt * 0.15, 2)
            c3_title = f"Review {cat2_name} Spending"
            c3_text = f"Your second highest spend is {cat2_name} (₹{cat2_amt:,.2f}). Saving 15% here frees up ₹{save_cat2:,.2f} for your emergency fund or investments."
        else:
            c3_title = "Automate Your Savings"
            c3_text = "Set up an automatic bank transfer to your savings goal on payday. Saving before you spend is the #1 rule of wealth building."
        ai_insights.append({"title": c3_title, "text": c3_text, "highlight": False})

    return {
        "full_name": current_user.full_name or "",
        "email": current_user.email or "",
        "total_balance": round(total_balance, 2),
        "monthly_income": round(monthly_income, 2),
        "monthly_expenses": round(monthly_expenses, 2),
        "savings_progress_pct": round(progress, 1),
        "recent_transactions": recent,
        "category_breakdown": dict(breakdown),
        "weekly_expenses": [round(w, 2) for w in weekly_expenses],
        "daily_expenses": [round(d, 2) for d in daily_expenses],
        "monthly_expense_totals": [round(mt, 2) for mt in monthly_expense_totals],
        "ai_insights": ai_insights,
    }


# ═══════════════════════════════════════════════════════════
#  Endpoint: Monthly Income (Profile)
# ═══════════════════════════════════════════════════════════
@app.get("/api/profile/income")
def get_monthly_income(
    current_user: models.User = Depends(get_current_user),
):
    return {"monthly_income": current_user.monthly_income or 0.0}


@app.put("/api/profile/income")
def set_monthly_income(
    body: schemas.MonthlyIncomeUpdate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    current_user.monthly_income = body.monthly_income
    db.commit()
    return {"monthly_income": current_user.monthly_income}


# ═══════════════════════════════════════════════════════════
#  Endpoints: Export (Excel & PDF)
# ═══════════════════════════════════════════════════════════
from fastapi.responses import StreamingResponse

@app.get("/api/export/excel")
def export_excel(
    date_from:    Optional[str] = None,
    date_to:      Optional[str] = None,
    category:     Optional[str] = None,
    txn_type:     Optional[str] = None,
    current_user: models.User   = Depends(get_current_user),
    db:           Session       = Depends(get_db),
):
    """Export filtered transactions as a styled Excel (.xlsx) file."""
    from export_engine import generate_excel

    df = _parse_date(date_from)
    dt = _parse_date(date_to)

    xlsx_bytes = generate_excel(db, current_user.id, current_user.email, df, dt, category, txn_type)
    filename = f"FinAly_Transactions_{datetime.now().strftime('%Y%m%d_%H%M')}.xlsx"

    return StreamingResponse(
        io.BytesIO(xlsx_bytes),
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/export/pdf")
def export_pdf(
    date_from:    Optional[str] = None,
    date_to:      Optional[str] = None,
    category:     Optional[str] = None,
    txn_type:     Optional[str] = None,
    current_user: models.User   = Depends(get_current_user),
    db:           Session       = Depends(get_db),
):
    """Export filtered transactions as a styled PDF report."""
    from export_engine import generate_pdf

    df = _parse_date(date_from)
    dt = _parse_date(date_to)

    pdf_bytes = generate_pdf(db, current_user.id, current_user.email, df, dt, category, txn_type)
    filename = f"FinAly_Report_{datetime.now().strftime('%Y%m%d_%H%M')}.pdf"

    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


def _parse_date(date_str: Optional[str]) -> Optional[datetime]:
    """Parse ISO date string or return None."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str)
    except ValueError:
        return None


# ═══════════════════════════════════════════════════════════
#  Endpoints: Transactions
# ═══════════════════════════════════════════════════════════
@app.get("/api/transactions", response_model=list[schemas.TransactionResponse])
def get_transactions(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(models.Transaction).filter(
        models.Transaction.user_id == current_user.id
    ).order_by(models.Transaction.date.desc()).all()


@app.post("/api/transactions", response_model=schemas.TransactionResponse,
          status_code=status.HTTP_201_CREATED)
def create_transaction(
    txn: schemas.TransactionCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_txn = models.Transaction(
        amount=txn.amount,
        category=txn.category,
        transaction_type=txn.transaction_type,
        description=txn.description,
        date=txn.date or datetime.now(timezone.utc),
        user_id=current_user.id,
    )
    db.add(new_txn)
    db.commit()
    db.refresh(new_txn)
    return new_txn


@app.delete("/api/transactions/{txn_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_transaction(
    txn_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    txn = db.query(models.Transaction).filter(
        models.Transaction.id == txn_id,
        models.Transaction.user_id == current_user.id
    ).first()
    if not txn:
        raise HTTPException(status_code=404, detail="Transaction not found.")
    db.delete(txn)
    db.commit()


# ═══════════════════════════════════════════════════════════
#  Endpoints: Budgets
# ═══════════════════════════════════════════════════════════
@app.get("/api/budgets", response_model=list[schemas.BudgetResponse])
def get_budgets(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(models.Budget).filter(
        models.Budget.user_id == current_user.id
    ).all()


@app.post("/api/budgets", response_model=schemas.BudgetResponse,
          status_code=status.HTTP_201_CREATED)
def create_budget(
    budget: schemas.BudgetCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_budget = models.Budget(
        category=budget.category,
        monthly_limit=budget.monthly_limit,
        month=budget.month,
        year=budget.year,
        user_id=current_user.id,
    )
    db.add(new_budget)
    db.commit()
    db.refresh(new_budget)
    return new_budget


@app.delete("/api/budgets/{budget_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_budget(
    budget_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    budget = db.query(models.Budget).filter(
        models.Budget.id == budget_id,
        models.Budget.user_id == current_user.id
    ).first()
    if not budget:
        raise HTTPException(status_code=404, detail="Budget not found.")
    db.delete(budget)
    db.commit()


@app.put("/api/budgets/{budget_id}", response_model=schemas.BudgetResponse)
def update_budget(
    budget_id: int,
    budget: schemas.BudgetCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_budget = db.query(models.Budget).filter(
        models.Budget.id == budget_id,
        models.Budget.user_id == current_user.id
    ).first()
    if not db_budget:
        raise HTTPException(status_code=404, detail="Budget not found.")
    db_budget.category = budget.category
    db_budget.monthly_limit = budget.monthly_limit
    db_budget.month = budget.month
    db_budget.year = budget.year
    db.commit()
    db.refresh(db_budget)
    return db_budget


# ═══════════════════════════════════════════════════════════
#  Endpoints: Savings Goals
# ═══════════════════════════════════════════════════════════
@app.get("/api/savings", response_model=list[schemas.SavingsGoalResponse])
def get_savings_goals(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    return db.query(models.SavingsGoal).filter(
        models.SavingsGoal.user_id == current_user.id
    ).all()


@app.post("/api/savings", response_model=schemas.SavingsGoalResponse,
          status_code=status.HTTP_201_CREATED)
def create_savings_goal(
    goal: schemas.SavingsGoalCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    new_goal = models.SavingsGoal(
        name=goal.name,
        target_amount=goal.target_amount,
        current_amount=goal.current_amount,
        deadline=goal.deadline,
        user_id=current_user.id,
    )
    db.add(new_goal)
    db.commit()
    db.refresh(new_goal)
    return new_goal


@app.put("/api/savings/{goal_id}", response_model=schemas.SavingsGoalResponse)
def update_savings_goal(
    goal_id: int,
    goal: schemas.SavingsGoalCreate,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_goal = db.query(models.SavingsGoal).filter(
        models.SavingsGoal.id == goal_id,
        models.SavingsGoal.user_id == current_user.id
    ).first()
    if not db_goal:
        raise HTTPException(status_code=404, detail="Savings goal not found.")
    db_goal.name = goal.name
    db_goal.target_amount = goal.target_amount
    db_goal.current_amount = goal.current_amount
    db_goal.deadline = goal.deadline
    db.commit()
    db.refresh(db_goal)
    return db_goal


@app.delete("/api/savings/{goal_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_savings_goal(
    goal_id: int,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    db_goal = db.query(models.SavingsGoal).filter(
        models.SavingsGoal.id == goal_id,
        models.SavingsGoal.user_id == current_user.id
    ).first()
    if not db_goal:
        raise HTTPException(status_code=404, detail="Savings goal not found.")
    db.delete(db_goal)
    db.commit()




# ═══════════════════════════════════════════════════════════
#  Endpoint: AI Chat — Gemini-Powered Financial Assistant
# ═══════════════════════════════════════════════════════════

class _ChatReq(_PydanticBase):
    message: str


# ── Gemini client initialisation (lazy, once) ──────────────
_gemini_client = None

def _get_gemini_client():
    """Lazy-init the Gemini client. Returns None if no API key."""
    global _gemini_client
    if _gemini_client is not None:
        return _gemini_client
    from config import GEMINI_API_KEY
    if not GEMINI_API_KEY:
        return None
    try:
        from google import genai
        _gemini_client = genai.Client(api_key=GEMINI_API_KEY)
        return _gemini_client
    except Exception as e:
        print(f"[Gemini] Failed to initialize client: {e}")
        return None


def _build_financial_context(db: Session, user_id: int, user_name: str) -> str:
    """
    Build a comprehensive snapshot of the user's financial data
    to inject into the Gemini prompt as context.
    """
    from datetime import timedelta
    now = datetime.now(timezone.utc)

    # User profile
    user = db.query(models.User).filter(models.User.id == user_id).first()
    monthly_income = user.monthly_income if user else 0.0

    # All transactions
    txns = db.query(models.Transaction).filter(
        models.Transaction.user_id == user_id
    ).all()

    # Overall totals
    total_income = sum(t.amount for t in txns if t.transaction_type == "Income")
    total_expense = sum(t.amount for t in txns if t.transaction_type == "Expense")
    total_balance = total_income - total_expense

    # Current month breakdown
    monthly_txns = [
        t for t in txns
        if t.date.month == now.month and t.date.year == now.year
    ]
    month_income = sum(t.amount for t in monthly_txns if t.transaction_type == "Income")
    month_expense = sum(t.amount for t in monthly_txns if t.transaction_type == "Expense")

    # Category breakdown (current month expenses)
    cat_breakdown: dict[str, float] = defaultdict(float)
    for t in monthly_txns:
        if t.transaction_type == "Expense":
            cat_breakdown[t.category] += t.amount
    sorted_cats = sorted(cat_breakdown.items(), key=lambda x: x[1], reverse=True)

    # Budgets
    budgets = db.query(models.Budget).filter(
        models.Budget.user_id == user_id,
        models.Budget.month == now.month,
        models.Budget.year == now.year,
    ).all()
    budget_lines = []
    for b in budgets:
        spent = cat_breakdown.get(b.category, 0.0)
        pct = round((spent / b.monthly_limit) * 100, 1) if b.monthly_limit > 0 else 0
        bstatus = "OVER BUDGET" if pct > 100 else ("Near limit" if pct > 80 else "OK")
        budget_lines.append(
            f"  - {b.category}: Budget Rs.{b.monthly_limit:,.2f} | Spent Rs.{spent:,.2f} ({pct}%) [{bstatus}]"
        )

    # Savings goals
    goals = db.query(models.SavingsGoal).filter(
        models.SavingsGoal.user_id == user_id
    ).all()
    goal_lines = []
    for g in goals:
        pct = round((g.current_amount / g.target_amount) * 100, 1) if g.target_amount > 0 else 0
        deadline_str = f", deadline: {g.deadline}" if g.deadline else ""
        goal_lines.append(
            f"  - {g.name}: Rs.{g.current_amount:,.2f} / Rs.{g.target_amount:,.2f} ({pct}%{deadline_str})"
        )

    # Recent transactions (last 10)
    recent = sorted(txns, key=lambda t: t.date, reverse=True)[:10]
    recent_lines = []
    for t in recent:
        sign = "+" if t.transaction_type == "Income" else "-"
        date_str = t.date.strftime("%d %b %Y") if hasattr(t.date, 'strftime') else str(t.date)[:10]
        desc = t.description or t.category
        recent_lines.append(f"  - {date_str}: {sign}Rs.{t.amount:,.2f} [{t.category}] {desc}")

    # ML forecast
    try:
        from ml_engine import run_classical_ml_analytics
        ml = run_classical_ml_analytics(db, user_id)
        forecast = ml.get("forecast")
        anomalies = ml.get("anomalies", [])
    except Exception:
        forecast = None
        anomalies = []

    forecast_str = ""
    if forecast:
        forecast_str = (
            f"\nSpending Forecast:\n"
            f"  - Last 30 days actual: Rs.{forecast['last_30d_actual']:,.2f}\n"
            f"  - Predicted next 30 days: Rs.{forecast['predicted_next_30d_expenses']:,.2f}\n"
            f"  - Trend: {forecast['expenditure_trend']}"
        )

    anomaly_str = ""
    if anomalies:
        anomaly_lines = [
            f"  - Rs.{a['amount']:,.2f} on {a['date']} [{a['category']}] — {a['description']} (z-score: {a['z_score']})"
            for a in anomalies[:3]
        ]
        anomaly_str = "\nUnusual Transactions (Anomalies):\n" + "\n".join(anomaly_lines)

    # Savings rate
    savings_rate_str = ""
    if monthly_income > 0 and month_expense > 0:
        rate = ((monthly_income - month_expense) / monthly_income) * 100
        savings_rate_str = f"\nSavings Rate: {rate:.1f}% (ideal target: 20%+)"

    cat_text = "\n".join(f"  - {cat}: Rs.{amt:,.2f}" for cat, amt in sorted_cats) if sorted_cats else "  (No expenses logged this month)"

    context = (
        "=== USER FINANCIAL DATA (REAL, LIVE) ===\n"
        f"Name: {user_name}\n"
        f"Fixed Monthly Income: Rs.{monthly_income:,.2f}\n"
        "\nOverall Totals:\n"
        f"  - Total Income: Rs.{total_income:,.2f}\n"
        f"  - Total Expenses: Rs.{total_expense:,.2f}\n"
        f"  - Net Balance: Rs.{total_balance:,.2f}\n"
        f"\nThis Month ({now.strftime('%B %Y')}):\n"
        f"  - Income: Rs.{month_income:,.2f}\n"
        f"  - Expenses: Rs.{month_expense:,.2f}\n"
        f"  - Net: Rs.{month_income - month_expense:,.2f}"
        f"{savings_rate_str}\n"
        f"\nCategory Breakdown (This Month):\n{cat_text}\n"
        "\nBudgets (This Month):\n"
        + ("\n".join(budget_lines) if budget_lines else "  (No budgets set)")
        + "\n\nSavings Goals:\n"
        + ("\n".join(goal_lines) if goal_lines else "  (No savings goals set)")
        + "\n\nRecent Transactions (Latest 10):\n"
        + ("\n".join(recent_lines) if recent_lines else "  (No transactions yet)")
        + forecast_str
        + anomaly_str
        + "\n=== END FINANCIAL DATA ==="
    )

    return context


_SYSTEM_PROMPT = (
    "You are FinAly AI, an intelligent personal finance assistant built for Indian users. "
    "You are warm, friendly, and expert in personal finance.\n\n"
    "CRITICAL RULES:\n"
    "1. You have access to the user's REAL financial data provided below the message. "
    "Use their ACTUAL numbers in your responses — never make up figures.\n"
    "2. Keep responses concise: 2-4 short paragraphs max. Use markdown formatting: "
    "**bold** for emphasis, bullet points for lists.\n"
    "3. Always use the Indian Rupee symbol for currency. Format large numbers Indian-style.\n"
    "4. Give specific, actionable advice based on their data. Don't be generic.\n"
    "5. If they ask about a feature of the app (budgets, transactions, savings goals, etc.), "
    "explain how to use it in FinAly AI.\n"
    "6. If their question is completely unrelated to finance or the app, politely redirect.\n"
    "7. Reference their specific categories, amounts, and goals by name when relevant.\n"
    "8. If they have anomalies or are over budget, proactively mention it.\n"
    "9. Be encouraging, not judgmental about spending habits.\n"
    "10. For investment advice, always add a disclaimer that this is educational, not SEBI-registered advice.\n\n"
    "ABOUT FINALY AI (the app):\n"
    "- Dashboard: Shows balance, income, expenses, charts (daily/weekly/monthly), AI insights\n"
    "- Transactions: Add/delete income and expense entries with categories\n"
    "- Budgets: Set monthly spending limits per category (Food, Transport, etc.)\n"
    "- Savings: Create goals with target amounts and deadlines, track progress\n"
    "- Bank: Connect bank accounts (Demo mode or Open Bank Project sandbox)\n"
    "- Export: Download transaction data as Excel or PDF reports\n"
    "- AI Chat: This is you! You answer questions about their finances.\n"
    "- Security: JWT auth + TOTP MFA (Google Authenticator)"
)


async def _ask_gemini(message: str, financial_context: str) -> Optional[str]:
    """
    Send the user's message + financial context to Gemini.
    Returns the response text, or None if Gemini is unavailable.
    """
    client = _get_gemini_client()
    if not client:
        return None

    from config import GEMINI_MODEL

    try:
        full_prompt = f"{financial_context}\n\nUser message: {message}"

        response = client.models.generate_content(
            model=GEMINI_MODEL,
            contents=full_prompt,
            config={
                "system_instruction": _SYSTEM_PROMPT,
                "temperature": 0.7,
                "max_output_tokens": 800,
            },
        )

        if response and response.text:
            return response.text.strip()
        return None

    except Exception as e:
        print(f"[Gemini] API error: {e}")
        return None


# ── Fallback: Original keyword-matching engine ─────────────
def _match(msg: str, keywords: list) -> bool:
    """True if ANY keyword/phrase appears in the message."""
    return any(kw in msg for kw in keywords)


def _generate_reply_fallback(msg: str, name: str, db, user_id: int) -> str:
    """Original keyword engine — used as fallback when Gemini is unavailable."""
    first = name.split()[0] if name else "there"

    if _match(msg, ["hello", "hi ", "hi!", "hey", "howdy", "good morning",
                    "good afternoon", "good evening", "greetings", "sup", "yo "]):
        return (
            f"Hey {first}! I'm **FinAly AI**, your personal "
            "finance assistant. I can help you with:\n\n"
            "• **Spending & expenses** — track and analyse where your money goes\n"
            "• **Budgets** — set monthly limits by category\n"
            "• **Savings goals** — plan and hit your financial milestones\n"
            "• **Investment tips** — SIPs, index funds, and more\n"
            "• **Account & security** — MFA, passwords, and profile settings\n\n"
            "What would you like help with today?"
        )

    if _match(msg, ["thank", "thanks", "awesome", "great", "perfect", "helpful",
                    "nice", "good job", "well done", "cheers"]):
        return (
            f"You're very welcome, {first}! That's what I'm here for. "
            "Is there anything else I can help you with today?"
        )

    if _match(msg, ["balance", "net worth", "total money", "how much do i have",
                    "how much money", "my money", "account balance"]):
        try:
            txns = db.query(models.Transaction).filter(
                models.Transaction.user_id == user_id
            ).all()
            income_total = sum(t.amount for t in txns if t.transaction_type == "Income")
            expense_total = sum(t.amount for t in txns if t.transaction_type == "Expense")
            balance = income_total - expense_total
            sign = "positive" if balance >= 0 else "negative"
            return (
                f"Your current **Total Balance** is **₹{balance:,.2f}** ({sign}).\n\n"
                f"Total Income recorded: ₹{income_total:,.2f}\n"
                f"Total Expenses recorded: ₹{expense_total:,.2f}\n\n"
                "Head to your **Dashboard** tab for a live animated view."
            )
        except Exception:
            pass
        return "Head to the **Dashboard** tab to see your balance with animated charts!"

    if _match(msg, ["expense", "spent", "spend", "spending", "how much did i",
                    "where did my money", "food", "rent", "transport", "utilities",
                    "entertainment", "shopping", "healthcare", "education"]):
        try:
            from datetime import datetime as _dt
            now = _dt.now(timezone.utc)
            txns = db.query(models.Transaction).filter(
                models.Transaction.user_id == user_id,
                models.Transaction.transaction_type == "Expense"
            ).all()
            monthly = [t for t in txns if t.date.month == now.month and t.date.year == now.year]
            total_month = sum(t.amount for t in monthly)
            breakdown: dict = defaultdict(float)
            for t in monthly:
                breakdown[t.category] += t.amount
            top_cats = sorted(breakdown.items(), key=lambda x: x[1], reverse=True)[:3]
            top_str = "\n".join(
                [f"  • **{cat}**: ₹{amt:,.2f}" for cat, amt in top_cats]
            ) if top_cats else "  (No expenses logged this month yet)"
            return (
                f"Here's your **spending summary for this month**:\n\n"
                f"Total spent: **₹{total_month:,.2f}**\n\n"
                f"Top categories:\n{top_str}\n\n"
                "*Tip: Use the **Dashboard** charts to see trends. Set a **Budget** to stay on track!*"
            )
        except Exception:
            pass
        return (
            "You can track your expenses in the **Transactions** tab.\n\n"
            "The **Dashboard** shows a real-time category breakdown donut chart and "
            "spending trend charts. Set a **Budget** to cap monthly spending per category!"
        )

    return (
        f"Hi {first}! I'm not quite sure I understood that, but I'm here to help!\n\n"
        "Here are some things you can ask me:\n"
        "  • *\"What's my total balance?\"*\n"
        "  • *\"How much did I spend this month?\"*\n"
        "  • *\"How do I set up a budget?\"*\n"
        "  • *\"Give me savings tips\"*\n"
        "  • *\"Should I invest in SIP?\"*\n\n"
        "Just type naturally — I'll do my best to understand!"
    )


@app.post("/api/chat")
async def chat(
    body: _ChatReq,
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    msg = body.message.strip()
    if not msg:
        return {"reply": "Go ahead, ask me anything!"}

    # Try Gemini first (intelligent, data-aware)
    financial_context = _build_financial_context(db, current_user.id, current_user.full_name)
    gemini_reply = await _ask_gemini(msg, financial_context)

    if gemini_reply:
        return {"reply": gemini_reply}

    # Fallback to keyword engine
    reply = _generate_reply_fallback(msg.lower(), current_user.full_name, db, current_user.id)
    return {"reply": reply}


# ═══════════════════════════════════════════════════════════
#  Endpoints: Bank Statement Import
# ═══════════════════════════════════════════════════════════

BANK_UPLOAD_MAX_BYTES = 10 * 1024 * 1024   # 10 MB hard cap
BANK_ALLOWED_MIME     = {"application/pdf", "text/csv", "text/plain",
                         "application/octet-stream", "application/vnd.ms-excel"}


@app.post("/api/bank/upload", response_model=schemas.BankPreviewResponse)
@limiter.limit("5/hour")
async def bank_upload(
    request:      Request,
    file:         UploadFile  = File(...),
    bank:         str         = Form("auto"),
    current_user: models.User = Depends(get_current_user),
):
    """
    Parse a bank statement (PDF or CSV) and return a preview.
    File is processed entirely in memory — never written to disk.
    Rate-limited to 5 uploads per hour per user.
    """
    # ── File size guard ─────────────────────────────────────────────
    file_bytes = await file.read(BANK_UPLOAD_MAX_BYTES + 1)
    if len(file_bytes) > BANK_UPLOAD_MAX_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File exceeds the 10 MB limit. Please upload a shorter date-range statement."
        )

    # ── Parse ──────────────────────────────────────────────────
    try:
        result = parse_statement(
            file_bytes,
            filename  = file.filename or "",
            bank_hint = bank.lower().strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    finally:
        del file_bytes   # ensure bytes are released

    rows = result.get("rows", [])
    return schemas.BankPreviewResponse(
        bank_detected = result.get("bank", "generic"),
        source        = result.get("source", "bank_csv"),
        rows          = [schemas.BankPreviewRow(**r) for r in rows],
        total_rows    = len(rows),
        parse_errors  = result.get("errors", [])[:20],   # cap error list
    )


@app.post("/api/bank/import", response_model=schemas.BankImportResponse)
async def bank_import(
    payload:      schemas.BankImportRequest,
    current_user: models.User  = Depends(get_current_user),
    db:           Session       = Depends(get_db),
):
    """
    Import user-confirmed rows from a previously parsed statement.
    Deduplicates against existing transactions using import_hash.
    Records an audit log entry in bank_import_logs.
    """
    VALID_CATEGORIES = {
        "Food", "Rent", "Transport", "Utilities", "Healthcare",
        "Entertainment", "Shopping", "Education", "Income", "Other",
    }
    VALID_TYPES = {"Income", "Expense"}

    imported = skipped_dup = skipped_invalid = 0
    new_txns: list[models.Transaction] = []

    # Pre-fetch existing import hashes for this user (fast dedup lookup)
    existing_hashes: set[str] = {
        row[0]
        for row in db.query(models.Transaction.import_hash)
                      .filter(
                          models.Transaction.user_id    == current_user.id,
                          models.Transaction.import_hash.isnot(None)
                      ).all()
    }

    for row in payload.rows:
        # ── Server-side validation (never trust client) ───────────────
        if row.transaction_type not in VALID_TYPES:
            skipped_invalid += 1
            continue
        if row.category not in VALID_CATEGORIES:
            row.category = "Other"   # sanitise unknown category
        try:
            txn_date = datetime.fromisoformat(row.date)
        except ValueError:
            skipped_invalid += 1
            continue
        if row.amount <= 0:
            skipped_invalid += 1
            continue

        # ── Dedup check ────────────────────────────────────────
        if row.import_hash in existing_hashes:
            skipped_dup += 1
            continue

        new_txns.append(models.Transaction(
            amount           = round(row.amount, 2),
            category         = row.category,
            transaction_type = row.transaction_type,
            description      = row.description[:255],
            date             = txn_date,
            user_id          = current_user.id,
            import_source    = payload.source,
            import_hash      = row.import_hash,
        ))
        existing_hashes.add(row.import_hash)   # prevent intra-batch dupes
        imported += 1

    # Bulk insert
    if new_txns:
        db.add_all(new_txns)

    # Audit log
    db.add(models.BankImportLog(
        user_id       = current_user.id,
        source        = payload.source,
        bank_hint     = payload.bank[:50],
        rows_parsed   = len(payload.rows),
        rows_imported = imported,
        rows_skipped  = skipped_invalid,
        rows_duplicate= skipped_dup,
    ))

    db.commit()

    return schemas.BankImportResponse(
        imported          = imported,
        skipped_duplicate = skipped_dup,
        skipped_invalid   = skipped_invalid,
        total_selected    = len(payload.rows),
    )


@app.get("/api/bank/import-history",
         response_model=list[schemas.BankImportLogResponse])
def bank_import_history(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Return the authenticated user's bank import audit log (newest first)."""
    return (
        db.query(models.BankImportLog)
          .filter(models.BankImportLog.user_id == current_user.id)
          .order_by(models.BankImportLog.created_at.desc())
          .limit(50)
          .all()
    )


@app.get("/api/bank/aa/link")
def bank_aa_link(
    current_user: models.User = Depends(get_current_user),
):
    """
    Account Aggregator integration stub (RBI AA Framework).
    Replace the provider_config block with real Setu / Perfios credentials
    to activate live bank-feed consent flows.
    """
    return {
        "status":            "stub",
        "consent_framework": "RBI Account Aggregator (AA)",
        "description": (
            "The Account Aggregator framework lets users securely share bank "
            "data with FinAly AI via a consent-based OAuth flow — no credentials shared."
        ),
        "providers": [
            {"name": "Setu AA",   "setup_url": "https://setu.co/aa"},
            {"name": "Perfios",   "setup_url": "https://www.perfios.com"},
            {"name": "Finbox",    "setup_url": "https://finbox.in"},
            {"name": "Yodlee",    "setup_url": "https://www.yodlee.com"},
        ],
        "activation_steps": [
            "1. Register as a Financial Information User (FIU) with an AA provider.",
            "2. Obtain client_id and client_secret from the AA provider.",
            "3. Add credentials to .env (AA_CLIENT_ID, AA_CLIENT_SECRET, AA_PROVIDER).",
            "4. Replace this stub with the provider's OAuth + data-fetch SDK.",
        ],
        "note": "This endpoint is ready for wiring. No code changes needed in the rest of the app.",
    }


# ═══════════════════════════════════════════════════════════
#  Endpoints: Live Banking Adapter (Mock / OBP)
# ═══════════════════════════════════════════════════════════

def _get_active_link(user_id: int, db: Session) -> Optional[models.LinkedBank]:
    """Return the user's active LinkedBank row, or None."""
    return (
        db.query(models.LinkedBank)
          .filter(models.LinkedBank.user_id == user_id,
                  models.LinkedBank.is_active == True)
          .order_by(models.LinkedBank.linked_at.desc())
          .first()
    )


@app.get("/api/bank/status", response_model=schemas.BankStatusOut)
def bank_status(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Check whether the current user has an active bank connection."""
    link = _get_active_link(current_user.id, db)
    if not link:
        return schemas.BankStatusOut(linked=False)
    return schemas.BankStatusOut(
        linked         = True,
        adapter        = link.adapter_type,
        bank_label     = link.bank_label,
        linked_at      = link.linked_at.isoformat() if link.linked_at else None,
        last_synced_at = link.last_synced_at.isoformat() if link.last_synced_at else None,
    )


@app.post("/api/bank/connect", response_model=schemas.BankConnectOut)
def bank_connect(
    payload:      schemas.BankConnectRequest,
    current_user: models.User = Depends(get_current_user),
    db:           Session      = Depends(get_db),
):
    """
    Authenticate with the chosen banking adapter and store encrypted token.
    For 'mock': works with any username (no real credentials needed).
    For 'obp':  requires OBP sandbox username + password.
    """
    try:
        adapter = get_banking_adapter(payload.adapter)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Build credentials dict for the adapter
    creds: dict = {}
    if payload.adapter == "mock":
        creds["username"]  = payload.username or current_user.email
        creds["mock_seed"] = payload.mock_seed or current_user.email
    elif payload.adapter == "obp":
        if not payload.username or not payload.password:
            raise HTTPException(status_code=400,
                                detail="OBP requires username and password.")
        creds = {
            "username":     payload.username,
            "password":     payload.password,
            "consumer_key": payload.consumer_key or "",
        }

    # Authenticate
    try:
        token_payload = adapter.authenticate(creds)
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))

    # Deactivate any previous link
    db.query(models.LinkedBank)\
      .filter(models.LinkedBank.user_id == current_user.id,
              models.LinkedBank.is_active == True)\
      .update({"is_active": False})

    # Encrypt the token payload
    import json as _json
    from security import encrypt_secret
    encrypted = encrypt_secret(_json.dumps(token_payload))

    bank_label = (
        "Demo Bank (Mock Mode)" if payload.adapter == "mock"
        else f"OBP Sandbox ({payload.username})"
    )

    link = models.LinkedBank(
        user_id         = current_user.id,
        adapter_type    = payload.adapter,
        bank_label      = bank_label,
        encrypted_token = encrypted,
        is_active       = True,
    )
    db.add(link)
    db.commit()

    return schemas.BankConnectOut(
        success    = True,
        adapter    = payload.adapter,
        bank_label = bank_label,
        message    = f" Connected to {bank_label} successfully!",
    )


@app.get("/api/bank/accounts", response_model=list[schemas.BankAccountOut])
def bank_accounts(
    current_user: models.User = Depends(get_current_user),
    db:           Session      = Depends(get_db),
):
    """Fetch bank accounts from the connected adapter."""
    link = _get_active_link(current_user.id, db)
    if not link:
        raise HTTPException(status_code=404,
                            detail="No bank connected. Please connect a bank first.")

    import json as _json
    from security import decrypt_secret
    try:
        token_payload = _json.loads(decrypt_secret(link.encrypted_token))
        adapter       = get_banking_adapter(link.adapter_type)
        accounts      = adapter.get_accounts(token_payload)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    # Update last sync time
    link.last_synced_at = datetime.now(timezone.utc)
    db.commit()

    return [schemas.BankAccountOut(**a) for a in accounts]


@app.get("/api/bank/transactions", response_model=list[schemas.BankTransactionOut])
def bank_transactions(
    account_id:   str,
    days:         int          = 90,
    current_user: models.User  = Depends(get_current_user),
    db:           Session       = Depends(get_db),
):
    """Fetch transactions for a specific account from the connected adapter."""
    link = _get_active_link(current_user.id, db)
    if not link:
        raise HTTPException(status_code=404,
                            detail="No bank connected. Please connect a bank first.")
    days = max(1, min(days, 365))

    import json as _json
    from security import decrypt_secret
    try:
        token_payload = _json.loads(decrypt_secret(link.encrypted_token))
        adapter       = get_banking_adapter(link.adapter_type)
        txns          = adapter.get_transactions(token_payload, account_id, days)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    link.last_synced_at = datetime.now(timezone.utc)
    db.commit()

    return [schemas.BankTransactionOut(**t) for t in txns]


@app.post("/api/bank/import-live", response_model=schemas.BankImportResponse)
def bank_import_live(
    payload:      schemas.BankImportFromAdapterRequest,
    current_user: models.User  = Depends(get_current_user),
    db:           Session       = Depends(get_db),
):
    """
    Pull transactions from the live adapter for a given account and
    import them into the FinAly AI transactions table.
    Deduplicates on import_hash — safe to call repeatedly.
    """
    link = _get_active_link(current_user.id, db)
    if not link:
        raise HTTPException(status_code=404, detail="No bank connected.")

    import json as _json
    from security import decrypt_secret
    try:
        token_payload = _json.loads(decrypt_secret(link.encrypted_token))
        adapter       = get_banking_adapter(link.adapter_type)
        txns          = adapter.get_transactions(token_payload, payload.account_id, payload.days)
    except ValueError as e:
        raise HTTPException(status_code=502, detail=str(e))

    VALID_CATEGORIES = {
        "Food", "Rent", "Transport", "Utilities", "Healthcare",
        "Entertainment", "Shopping", "Education", "Income", "Other",
    }

    existing_hashes: set[str] = {
        row[0]
        for row in db.query(models.Transaction.import_hash)
                      .filter(models.Transaction.user_id == current_user.id,
                              models.Transaction.import_hash.isnot(None)).all()
    }

    imported = skipped_dup = skipped_invalid = 0
    new_txns: list[models.Transaction] = []

    for t in txns:
        if t["import_hash"] in existing_hashes:
            skipped_dup += 1
            continue
        if t["type"] not in {"Income", "Expense"} or t["amount"] <= 0:
            skipped_invalid += 1
            continue
        category = t["category"] if t["category"] in VALID_CATEGORIES else "Other"
        try:
            txn_date = datetime.fromisoformat(t["date"])
        except ValueError:
            skipped_invalid += 1
            continue

        new_txns.append(models.Transaction(
            amount           = round(t["amount"], 2),
            category         = category,
            transaction_type = t["type"],
            description      = t["description"][:255],
            date             = txn_date,
            user_id          = current_user.id,
            import_source    = f"bank_{link.adapter_type}",
            import_hash      = t["import_hash"],
        ))
        existing_hashes.add(t["import_hash"])
        imported += 1

    if new_txns:
        db.add_all(new_txns)

    db.add(models.BankImportLog(
        user_id       = current_user.id,
        source        = f"bank_{link.adapter_type}",
        bank_hint     = link.bank_label,
        rows_parsed   = len(txns),
        rows_imported = imported,
        rows_skipped  = skipped_invalid,
        rows_duplicate= skipped_dup,
    ))

    link.last_synced_at = datetime.now(timezone.utc)
    db.commit()

    return schemas.BankImportResponse(
        imported          = imported,
        skipped_duplicate = skipped_dup,
        skipped_invalid   = skipped_invalid,
        total_selected    = len(txns),
    )


@app.delete("/api/bank/disconnect")
def bank_disconnect(
    current_user: models.User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke the user's active bank connection and delete the encrypted token."""
    updated = (
        db.query(models.LinkedBank)
          .filter(models.LinkedBank.user_id == current_user.id,
                  models.LinkedBank.is_active == True)
          .update({"is_active": False})
    )
    db.commit()
    if updated == 0:
        raise HTTPException(status_code=404, detail="No active bank connection found.")
    return {"message": "Bank disconnected successfully."}


# ═══════════════════════════════════════════════════════════
#  Static Files & Frontend Serving (SPA Root Routes)
# ═══════════════════════════════════════════════════════════
import os
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

_BASE_DIR = os.path.dirname(os.path.abspath(__file__))

@app.api_route("/", methods=["GET", "HEAD"], response_class=FileResponse)
async def serve_index():
    """Serve the main dashboard HTML at root (http://localhost:8000/)."""
    index_path = os.path.join(_BASE_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    raise HTTPException(status_code=404, detail="index.html not found")

@app.api_route("/login", methods=["GET", "HEAD"], response_class=FileResponse)
@app.api_route("/login.html", methods=["GET", "HEAD"], response_class=FileResponse)
async def serve_login():
    """Serve the login HTML at /login or /login.html."""
    login_path = os.path.join(_BASE_DIR, "login.html")
    if os.path.exists(login_path):
        return FileResponse(login_path)
    raise HTTPException(status_code=404, detail="login.html not found")

@app.api_route("/index.html", methods=["GET", "HEAD"], response_class=FileResponse)
async def serve_index_direct():
    return await serve_index()

# Mount the current folder for static assets (.js, .css, images, etc.)
app.mount("/", StaticFiles(directory=_BASE_DIR), name="static")


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run("main:app", host="0.0.0.0", port=port)