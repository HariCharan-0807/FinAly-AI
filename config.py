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

# ── Email — Resend API (HTTPS, works on Railway free tier) ───
# Sign up free at https://resend.com — 3,000 emails/month
RESEND_API_KEY = os.getenv("RESEND_API_KEY", "")
# Resend requires a verified sender. Use their free test address before adding your domain:
#   "FinAly AI <onboarding@resend.dev>"  (can only send to your own Resend account email)
# After adding a domain in Resend dashboard → use: "FinAly AI <noreply@yourdomain.com>"
RESEND_FROM    = os.getenv("RESEND_FROM", "FinAly AI <onboarding@resend.dev>")
RESEND_ENABLED = bool(RESEND_API_KEY)

# Keep SMTP vars for backwards compat (not used anymore)
SMTP_HOST     = os.getenv("SMTP_HOST", "smtp.gmail.com")
SMTP_PORT     = int(os.getenv("SMTP_PORT", "587"))
SMTP_FROM     = os.getenv("SMTP_FROM_EMAIL", "")
SMTP_PASSWORD = os.getenv("SMTP_PASSWORD", "")
SMTP_ENABLED  = RESEND_ENABLED   # alias — always use Resend now

OTP_EXPIRE_MINUTES         = 10
RESET_TOKEN_EXPIRE_MINUTES = 10