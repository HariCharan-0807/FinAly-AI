import bcrypt
import pyotp
import qrcode
import io
import base64
from cryptography.fernet import Fernet
from config import FERNET_KEY, TOTP_ISSUER_NAME

# ── Password hashing (bcrypt directly — passlib incompatible with bcrypt 4+) ─
def get_password_hash(password: str) -> str:
    """Hash a password with bcrypt (work factor 12)."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    """Verify a plain password against a bcrypt hash."""
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


# ── Fernet encryption for MFA secrets at rest ───────────────
_fernet = Fernet(FERNET_KEY.encode() if isinstance(FERNET_KEY, str) else FERNET_KEY)

def encrypt_secret(plain_text: str) -> str:
    """Encrypt a TOTP secret before storing in DB."""
    return _fernet.encrypt(plain_text.encode()).decode()

def decrypt_secret(cipher_text: str) -> str:
    """Decrypt a TOTP secret retrieved from DB."""
    return _fernet.decrypt(cipher_text.encode()).decode()


# ── TOTP (Time-based One-Time Password) ─────────────────────
def generate_totp_secret() -> str:
    """Generate a new random TOTP secret (base32)."""
    return pyotp.random_base32()

def get_totp_uri(secret: str, user_email: str) -> str:
    """Build the otpauth:// URI for QR code generation."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=user_email, issuer_name=TOTP_ISSUER_NAME)

def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code (allows ±30 second drift)."""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)

def get_totp_qr_base64(uri: str) -> str:
    """Generate a QR code PNG from the URI and return as base64 string."""
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()