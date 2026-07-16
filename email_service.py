"""
FinAly AI — Email Service (Gmail API / OAuth2)
Sends emails via Google's official Gmail API over HTTPS (port 443).
This works on Railway free tier and sends from the actual Gmail address
with proper SPF/DKIM — guaranteed inbox delivery.

Setup: Run `python setup_gmail.py` once locally to get OAuth2 credentials.
"""
import base64
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

from config import (
    GMAIL_CLIENT_ID, GMAIL_CLIENT_SECRET, GMAIL_REFRESH_TOKEN,
    GMAIL_FROM, EMAIL_ENABLED,
)


def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def _get_gmail_service():
    """Build a Gmail API service using OAuth2 refresh token."""
    from google.oauth2.credentials import Credentials
    from googleapiclient.discovery import build

    creds = Credentials(
        token=None,
        refresh_token=GMAIL_REFRESH_TOKEN,
        token_uri="https://oauth2.googleapis.com/token",
        client_id=GMAIL_CLIENT_ID,
        client_secret=GMAIL_CLIENT_SECRET,
        scopes=["https://www.googleapis.com/auth/gmail.send"],
    )
    return build("gmail", "v1", credentials=creds, cache_discovery=False)


def _send(to_email: str, subject: str, html_body: str) -> bool:
    """Send email via Gmail API. Returns True on success."""
    if not EMAIL_ENABLED:
        print(f"[Email] Gmail API not configured — skipping '{subject}' to {to_email}")
        return False

    try:
        service = _get_gmail_service()

        msg = MIMEMultipart("alternative")
        msg["From"]    = f"FinAly AI <{GMAIL_FROM}>"
        msg["To"]      = to_email
        msg["Subject"] = subject
        msg.attach(MIMEText(html_body, "html"))

        raw = base64.urlsafe_b64encode(msg.as_bytes()).decode("utf-8")
        result = service.users().messages().send(
            userId="me",
            body={"raw": raw}
        ).execute()

        print(f"[Email] ✅ Sent '{subject}' to {to_email} (id: {result.get('id', '?')})")
        return True

    except Exception as e:
        print(f"[Email] ❌ Gmail API error: {e}")
        return False


def send_otp_email(to_email: str, otp: str, purpose: str = "verification") -> bool:
    if purpose == "password_reset":
        subject = "FinAly AI — Password Reset Code"
        action  = "reset your password"
        icon    = "🔐"
    else:
        subject = "FinAly AI — Verify Your Email"
        action  = "verify your email address"
        icon    = "✅"

    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family:Inter,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px;">
      <div style="max-width:480px;margin:0 auto;background:#1e293b;border-radius:16px;padding:32px;border:1px solid rgba(79,70,229,0.3);">
        <div style="text-align:center;margin-bottom:24px;">
          <span style="font-size:36px;font-weight:800;color:#4f46e5;">₹ FinAly AI</span>
        </div>
        <h2 style="color:#f8fafc;margin:0 0 8px;">{icon} Your One-Time Code</h2>
        <p style="color:#94a3b8;margin:0 0 24px;">Use this code to {action}. It expires in <strong>10 minutes</strong>.</p>
        <div style="background:#0f172a;border-radius:12px;padding:28px;text-align:center;margin:24px 0;border:2px solid #4f46e5;">
          <span style="font-size:48px;font-weight:900;letter-spacing:16px;color:#4f46e5;">{otp}</span>
        </div>
        <p style="color:#64748b;font-size:13px;margin:0;">If you didn't request this, you can safely ignore this email. Your account is secure.</p>
        <hr style="border:none;border-top:1px solid #334155;margin:24px 0;">
        <p style="color:#475569;font-size:12px;text-align:center;margin:0;">FinAly AI · AI-Powered Personal Finance · Protected by 256-bit encryption</p>
      </div>
    </body>
    </html>
    """
    return _send(to_email, subject, html)


def send_welcome_email(to_email: str, full_name: str) -> bool:
    first_name = full_name.split()[0] if full_name else "there"
    html = f"""
    <!DOCTYPE html>
    <html>
    <head><meta charset="UTF-8"></head>
    <body style="font-family:Inter,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px;">
      <div style="max-width:480px;margin:0 auto;background:#1e293b;border-radius:16px;padding:32px;border:1px solid rgba(79,70,229,0.3);">
        <div style="text-align:center;margin-bottom:24px;">
          <span style="font-size:36px;font-weight:800;color:#4f46e5;">₹ FinAly AI</span>
        </div>
        <h2 style="color:#f8fafc;margin:0 0 8px;">Welcome, {first_name}! 🎉</h2>
        <p style="color:#94a3b8;margin:0 0 16px;">Your email is verified and your account is ready.</p>
        <ul style="color:#94a3b8;padding-left:20px;margin:0 0 24px;">
          <li style="margin-bottom:8px;">📊 Track expenses &amp; income</li>
          <li style="margin-bottom:8px;">🎯 Set savings goals &amp; budgets</li>
          <li style="margin-bottom:8px;">🤖 AI-powered spending forecasts</li>
          <li style="margin-bottom:8px;">🔒 Enable MFA for extra security</li>
        </ul>
        <hr style="border:none;border-top:1px solid #334155;margin:24px 0;">
        <p style="color:#475569;font-size:12px;text-align:center;margin:0;">FinAly AI · AI-Powered Personal Finance</p>
      </div>
    </body>
    </html>
    """
    return _send(to_email, "Welcome to FinAly AI! 🎉", html)
