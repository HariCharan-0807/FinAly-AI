"""
FinAly AI — Email Service
Sends OTP emails using Gmail SMTP (TLS).
If SMTP is not configured, returns False gracefully so the app still works.
"""
import smtplib
import random
import string
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from config import SMTP_HOST, SMTP_PORT, SMTP_FROM, SMTP_PASSWORD, SMTP_ENABLED


def _generate_otp(length: int = 6) -> str:
    """Generate a numeric OTP of given length."""
    return ''.join(random.choices(string.digits, k=length))


def _send(to_email: str, subject: str, html_body: str) -> bool:
    """Send an email. Returns True on success, False if SMTP not configured or on error."""
    if not SMTP_ENABLED:
        print(f"[Email] SMTP not configured — would have sent '{subject}' to {to_email}")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"]    = f"FinAly AI <{SMTP_FROM}>"
        msg["To"]      = to_email
        msg.attach(MIMEText(html_body, "html"))

        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls()
            server.login(SMTP_FROM, SMTP_PASSWORD)
            server.sendmail(SMTP_FROM, to_email, msg.as_string())
        return True
    except Exception as e:
        print(f"[Email] Failed to send to {to_email}: {e}")
        return False


def send_otp_email(to_email: str, otp: str, purpose: str = "verification") -> bool:
    """
    Send a 6-digit OTP email.
    purpose: 'verification' | 'password_reset'
    """
    if purpose == "password_reset":
        subject = "FinAly AI — Password Reset Code"
        action  = "reset your password"
    else:
        subject = "FinAly AI — Verify Your Email"
        action  = "verify your email address"

    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family:Inter,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px;">
      <div style="max-width:480px;margin:0 auto;background:#1e293b;border-radius:16px;padding:32px;border:1px solid rgba(79,70,229,0.3);">
        <div style="text-align:center;margin-bottom:24px;">
          <span style="font-size:36px;font-weight:800;background:linear-gradient(135deg,#4f46e5,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">₹ FinAly AI</span>
        </div>
        <h2 style="color:#f8fafc;margin:0 0 8px;">Your One-Time Code</h2>
        <p style="color:#94a3b8;margin:0 0 24px;">Use this code to {action}. It expires in <strong>10 minutes</strong>.</p>
        <div style="background:#0f172a;border-radius:12px;padding:24px;text-align:center;margin:24px 0;border:1px solid rgba(79,70,229,0.4);">
          <span style="font-size:42px;font-weight:900;letter-spacing:12px;color:#4f46e5;">{otp}</span>
        </div>
        <p style="color:#64748b;font-size:13px;margin:0;">If you didn't request this, ignore this email. Your account is safe.</p>
        <hr style="border:none;border-top:1px solid #1e293b;margin:24px 0;">
        <p style="color:#475569;font-size:12px;text-align:center;margin:0;">FinAly AI · AI-Powered Personal Finance · Protected by 256-bit encryption</p>
      </div>
    </body>
    </html>
    """
    return _send(to_email, subject, html)


def send_welcome_email(to_email: str, full_name: str) -> bool:
    """Send a welcome email after successful email verification."""
    subject = "Welcome to FinAly AI! 🎉"
    first_name = full_name.split()[0] if full_name else "there"
    html = f"""
    <!DOCTYPE html>
    <html>
    <body style="font-family:Inter,Arial,sans-serif;background:#0f172a;color:#e2e8f0;margin:0;padding:20px;">
      <div style="max-width:480px;margin:0 auto;background:#1e293b;border-radius:16px;padding:32px;border:1px solid rgba(79,70,229,0.3);">
        <div style="text-align:center;margin-bottom:24px;">
          <span style="font-size:36px;font-weight:800;background:linear-gradient(135deg,#4f46e5,#7c3aed);-webkit-background-clip:text;-webkit-text-fill-color:transparent;">₹ FinAly AI</span>
        </div>
        <h2 style="color:#f8fafc;margin:0 0 8px;">Welcome, {first_name}! 🎉</h2>
        <p style="color:#94a3b8;margin:0 0 16px;">Your account is verified and ready. Start tracking your finances smarter.</p>
        <ul style="color:#94a3b8;padding-left:20px;margin:0 0 24px;">
          <li style="margin-bottom:8px;">📊 Track expenses &amp; income</li>
          <li style="margin-bottom:8px;">🎯 Set savings goals</li>
          <li style="margin-bottom:8px;">🤖 Get AI-powered spending forecasts</li>
          <li style="margin-bottom:8px;">🔒 Enable MFA for extra security</li>
        </ul>
        <hr style="border:none;border-top:1px solid #334155;margin:24px 0;">
        <p style="color:#475569;font-size:12px;text-align:center;margin:0;">FinAly AI · AI-Powered Personal Finance</p>
      </div>
    </body>
    </html>
    """
    return _send(to_email, subject, html)


def generate_otp() -> str:
    """Public helper to generate a 6-digit OTP."""
    return _generate_otp(6)
