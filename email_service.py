"""
FinAly AI — Email Service (Google Apps Script Webhook)
Sends emails via a Google Apps Script web app that uses GmailApp.sendEmail().
This bypasses Railway's SMTP port blocks (uses HTTPS/443) and sends from
the actual Gmail account — perfect SPF/DKIM, 100% free, no domain needed.

Limit: ~100 emails/day (free Gmail) — more than enough for a project.
"""
import random
import string
import requests as _requests

from config import GMAIL_WEBHOOK_URL, EMAIL_ENABLED


def generate_otp(length: int = 6) -> str:
    return ''.join(random.choices(string.digits, k=length))


def _send(to_email: str, subject: str, html_body: str) -> bool:
    """Send email via Google Apps Script webhook. Returns True on success."""
    if not EMAIL_ENABLED:
        print(f"[Email] No email provider configured — skipping '{subject}' to {to_email}")
        return False

    payload = {
        "to": to_email,
        "subject": subject,
        "html": html_body,
    }

    try:
        # Google Apps Script redirects POST (302) — follow manually keeping POST method
        resp = _requests.post(
            GMAIL_WEBHOOK_URL,
            json=payload,
            timeout=30,
            allow_redirects=False,  # Don't auto-follow (it converts POST→GET)
        )

        # Follow the redirect manually as POST
        if resp.status_code in (301, 302, 303, 307, 308):
            redirect_url = resp.headers.get('Location', '')
            if redirect_url:
                resp = _requests.post(
                    redirect_url,
                    json=payload,
                    timeout=30,
                    allow_redirects=True,
                )

        if resp.status_code == 200:
            try:
                data = resp.json()
                if data.get('success'):
                    print(f"[Email] ✅ Sent '{subject}' to {to_email}")
                    return True
            except Exception:
                pass
            # Even if we can't parse JSON, 200 usually means success
            print(f"[Email] ✅ Sent '{subject}' to {to_email} (status 200)")
            return True
        else:
            print(f"[Email] ❌ Webhook error {resp.status_code}: {resp.text[:300]}")
            return False
    except Exception as e:
        print(f"[Email] ❌ Request failed: {e}")
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
