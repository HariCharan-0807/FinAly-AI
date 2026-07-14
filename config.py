import os
from dotenv import load_dotenv

load_dotenv(override=True)

# ── JWT / Auth ──────────────────────────────────────────────
SECRET_KEY = os.getenv("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set. Create a .env file.")

REFRESH_SECRET_KEY = os.getenv("REFRESH_SECRET_KEY")
if not REFRESH_SECRET_KEY:
    raise ValueError("REFRESH_SECRET_KEY is not set in .env file.")

ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
REFRESH_TOKEN_EXPIRE_DAYS = 7

# ── MFA ─────────────────────────────────────────────────────
FERNET_KEY = os.getenv("FERNET_KEY")
if not FERNET_KEY:
    raise ValueError("FERNET_KEY is not set in .env file.")

TOTP_ISSUER_NAME = os.getenv("TOTP_ISSUER_NAME", "FinAlyAI")

# ── Database ─────────────────────────────────────────────────
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./.finaly_ai.db")

# ── Security ─────────────────────────────────────────────────
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_MINUTES = 15