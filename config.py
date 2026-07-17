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

# ── Email — Gmail API (OAuth2, HTTPS/443, works on Railway) ──
# Uses Google's official Gmail API — sends from your actual Gmail address
# with proper SPF/DKIM authentication. 100% free, no domain needed.
GMAIL_CLIENT_ID     = os.getenv("GMAIL_CLIENT_ID", "")
GMAIL_CLIENT_SECRET = os.getenv("GMAIL_CLIENT_SECRET", "")
GMAIL_REFRESH_TOKEN = os.getenv("GMAIL_REFRESH_TOKEN", "")
GMAIL_FROM          = os.getenv("GMAIL_FROM", "finalyai.help@gmail.com")
EMAIL_ENABLED       = bool(GMAIL_CLIENT_ID and GMAIL_CLIENT_SECRET and GMAIL_REFRESH_TOKEN)

# Backward compat aliases
SMTP_ENABLED = EMAIL_ENABLED
SMTP_FROM    = GMAIL_FROM

OTP_EXPIRE_MINUTES         = 10
RESET_TOKEN_EXPIRE_MINUTES = 10

# ── Gemini AI (Intelligent Chat) ──────────────────────────
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY", "")
GEMINI_MODEL   = os.getenv("GEMINI_MODEL", "gemini-2.0-flash")