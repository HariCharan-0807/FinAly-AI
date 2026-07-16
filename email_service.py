"""
FinAly AI — Email Service (Brevo / Resend)
Uses HTTPS APIs (port 443) so it works on Railway's free tier.
Brevo = 300 emails/day free to ANY recipient. No domain needed.
"""
import random
import string
import requests as _requests

from config import (
    BREVO_API_KEY, BREVO_FROM, BREVO_ENABLED,
    RESEND_API_KEY, RESEND_FROM, RESEND_ENABLED,
    EMAIL_ENABLED,
)


def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def _send(to_email: str, subject: str, html_body: str) -> bool:
    """Send email via Brevo (priority) or Resend. Returns True on success."""
    if not EMAIL_ENABLED:
        print(f"[Email] No email provider configured — skipping '{subject}' to {to_email}")
        return False

    if BREVO_ENABLED:
        return _send_brevo(to_email, subject, html_body)
    else:
        return _send_resend(to_email, subject, html_body)


def _send_brevo(to_email: str, subject: str, html_body: str) -> bool:
    """Send via Brevo (Sendinblue) HTTPS API."""
    try:
        resp = _requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={
                "api-key": BREVO_API_KEY,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            json={
                "sender": {"name": "FinAly AI", "email": BREVO_FROM},
                "to": [{"email": to_email}],
                "subject": subject,
                "htmlContent": html_body,
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            print(f"[Email/Brevo] ✅ Sent '{subject}' to {to_email}")
            return True
        else:
            print(f"[Email/Brevo] ❌ Error {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[Email/Brevo] ❌ Request failed: {e}")
        return False


def _send_resend(to_email: str, subject: str, html_body: str) -> bool:
    """Send via Resend HTTPS API (fallback)."""
    try:
        resp = _requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {RESEND_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "from": RESEND_FROM,
                "to": [to_email],
                "subject": subject,
                "html": html_body,
            },
            timeout=15,
        )
        if resp.status_code in (200, 201):
            print(f"[Email/Resend] ✅ Sent '{subject}' to {to_email}")
            return True
        else:
            print(f"[Email/Resend] ❌ Error {resp.status_code}: {resp.text}")
            return False
    except Exception as e:
        print(f"[Email/Resend] ❌ Request failed: {e}")
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
    return _send(to_email, f"Welcome to FinAly AI! 🎉", html)
