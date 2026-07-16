import os
from dotenv import load_dotenv

load_dotenv(override=True)

# ── JWT / Auth ──────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY", "finaly_ai_secret_key_production_default_98234729384729384")
REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY", "finaly_ai_refresh_secret_production_default_847293847293847")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ── MFA ─────────────────────────────────────────────────────
FERNET_KEY = os.getenv("FERNET_KEY", "GUz_Y-8BA1LS9l9Ic3okIqnDvkM80d2T0nuSCkKsq2o=")

TOTP_ISSUER_NAME = os.getenv("TOTP_ISSUER_NAME", "FinAlyAI")

# ── Database ─────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./.finaly_ai.db")

# ── Security ─────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15

# ── Email — Google Apps Script Webhook (100% free, uses Gmail) ──
# Sends via Gmail's own servers = perfect deliverability, no domain needed
GMAIL_WEBHOOK_URL = os.getenv("GMAIL_WEBHOOK_URL", "")
EMAIL_ENABLED     = bool(GMAIL_WEBHOOK_URL)

# Backward compat aliases
SMTP_ENABLED = EMAIL_ENABLED
SMTP_FROM    = os.getenv("SMTP_FROM_EMAIL", "finalyai.help@gmail.com")

OTP_EXPIRE_MINUTES         = 10
RESET_TOKEN_EXPIRE_MINUTES = 10