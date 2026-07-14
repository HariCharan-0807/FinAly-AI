/**
 * FinAly AI — auth.js
 * Handles signup, login, MFA setup, MFA verify, token management.
 * Security: tokens stored in sessionStorage only.
 */

const API = (
  document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
  'https://web-production-c2931.up.railway.app'
).replace(/\/$/, '');

// ═══════════════════════════════════════════════════════════
//  Toast Notifications
// ═══════════════════════════════════════════════════════════
function showToast(message, type = 'info', duration = 4000) {
  const toast = document.getElementById('toast');
  if (!toast) return;
  toast.textContent = message;
  toast.className = `toast ${type} show`;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.className = 'toast'; }, duration);
}

// ═══════════════════════════════════════════════════════════
//  Loading States
// ═══════════════════════════════════════════════════════════
function setLoading(btnId, isLoading) {
  const btn = document.getElementById(btnId);
  if (!btn) return;
  const text    = btn.querySelector('.btn-text');
  const spinner = btn.querySelector('.btn-spinner');
  btn.disabled = isLoading;
  if (spinner) spinner.classList.toggle('hidden', !isLoading);
  if (text && btn.dataset.label) {
    text.textContent = isLoading ? 'Please wait…' : btn.dataset.label;
  }
}

// ═══════════════════════════════════════════════════════════
//  View Toggling
// ═══════════════════════════════════════════════════════════
function toggleView(formId) {
  ['login-form', 'signup-form', 'mfa-form', 'mfa-setup-form'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.classList.add('hidden');
  });
  const target = document.getElementById(formId);
  if (target) target.classList.remove('hidden');
  // Persist the current view so page refresh restores it
  sessionStorage.setItem('auth_view', formId);
}

// ═══════════════════════════════════════════════════════════
//  Show/Hide Password
// ═══════════════════════════════════════════════════════════
function togglePwd(inputId, btn) {
  const input = document.getElementById(inputId);
  if (!input) return;
  const isHidden = input.type === 'password';
  input.type = isHidden ? 'text' : 'password';
  // SVG eye-open / eye-off icons
  if (isHidden) {
    btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>';
  } else {
    btn.innerHTML = '<svg viewBox="0 0 24 24"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>';
  }
}

// ═══════════════════════════════════════════════════════════
//  Password Strength Meter
// ═══════════════════════════════════════════════════════════
function updateStrengthMeter(password) {
  const bar   = document.getElementById('strength-bar');
  const label = document.getElementById('strength-label');
  if (!bar || !label) return;

  let score = 0;
  if (password.length >= 8)  score++;
  if (/[A-Z]/.test(password)) score++;
  if (/[a-z]/.test(password)) score++;
  if (/\d/.test(password))    score++;
  if (/[!@#$%^&*()\-_=+\[\]{};:'",.<>/?\\|`~]/.test(password)) score++;

  const levels = [
    { color: '#ef4444', label: 'Too weak',  width: '10%'  },
    { color: '#f97316', label: 'Weak',      width: '30%'  },
    { color: '#f59e0b', label: 'Fair',      width: '55%'  },
    { color: '#22c55e', label: 'Good',      width: '80%'  },
    { color: '#10b981', label: 'Strong ',  width: '100%' },
  ];
  const level = levels[Math.max(0, score - 1)] || levels[0];
  bar.style.width           = password.length ? level.width : '0%';
  bar.style.backgroundColor = level.color;
  label.textContent         = password.length ? level.label : '';
  label.style.color         = level.color;
}

// ═══════════════════════════════════════════════════════════
//  Restore view on page load (handles page refresh)
// ═══════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
  // Set DOB max date for 18+ check
  const dobInput = document.getElementById('signup-dob');
  if (dobInput) {
    const maxDate = new Date();
    maxDate.setFullYear(maxDate.getFullYear() - 18);
    dobInput.setAttribute('max', maxDate.toISOString().split('T')[0]);
  }

  // Store original button labels
  document.querySelectorAll('.primary-btn').forEach(btn => {
    const text = btn.querySelector('.btn-text');
    if (text) btn.dataset.label = text.textContent;
  });

  // ── Restore state on page refresh ──
  const savedView  = sessionStorage.getItem('auth_view');
  const savedToken = sessionStorage.getItem('finaly_token');
  const savedUri   = sessionStorage.getItem('mfa_totp_uri');
  const savedEmail = sessionStorage.getItem('finaly_email');

  if (savedView === 'mfa-setup-form' && savedToken && savedUri) {
    // User refreshed while on the MFA setup screen — restore it
    renderQrCode(savedUri, sessionStorage.getItem('mfa_secret') || '', sessionStorage.getItem('mfa_qr_base64') || null);
    toggleView('mfa-setup-form');
    showToast(' Scan the QR code with your authenticator app, then enter the 6-digit code.', 'info', 8000);
  } else if (savedView === 'mfa-form' && savedToken) {
    // User refreshed while on the OTP entry screen — restore it
    toggleView('mfa-form');
    showToast(' Please enter your 6-digit authenticator code.', 'info');
  } else {
    // Default: show login form
    toggleView('login-form');
  }

  // Pre-fill email if stored
  if (savedEmail) {
    const loginEmailEl = document.getElementById('login-email');
    if (loginEmailEl && !loginEmailEl.value) loginEmailEl.value = savedEmail;
  }
});

// ═══════════════════════════════════════════════════════════
//  QR Code Renderer (always embedded — never a separate tab)
// ═══════════════════════════════════════════════════════════
function renderQrCode(uri, secret, qrBase64 = null) {
  const qrContainer    = document.getElementById('qr-container');
  const secretDisplay  = document.getElementById('totp-secret-display');

  if (!qrContainer) return;

  // Prefer offline base64 image generated by Python backend; fallback to QR Server API
  const encoded = encodeURIComponent(uri || '');
  const imgSrc  = qrBase64 || `https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=${encoded}&bgcolor=ffffff&color=000000&format=png`;

  qrContainer.innerHTML = `
    <div style="background:#fff;padding:12px;border-radius:14px;display:inline-block;box-shadow:0 4px 24px rgba(0,0,0,0.5);">
      <img
        src="${imgSrc}"
        alt="MFA QR code — scan with Google Authenticator or Authy"
        width="180"
        height="180"
        style="display:block;border-radius:6px;"
        onerror="this.style.display='none';document.getElementById('qr-fallback').style.display='block';"
      >
    </div>`;
    <p id="qr-fallback" style="display:none;color:#f97316;font-size:13px;margin-top:10px;">
      ️ Image failed to load. Use the manual key below.
    </p>`;

  if (secretDisplay && secret) secretDisplay.textContent = secret;
}

// ═══════════════════════════════════════════════════════════
//  SIGN UP
// ═══════════════════════════════════════════════════════════
async function handleSignup(event) {
  event.preventDefault();

  const fullName = document.getElementById('signup-name').value.trim();
  const email    = document.getElementById('signup-email').value.trim();
  const dob      = document.getElementById('signup-dob').value;
  const password = document.getElementById('signup-password').value;
  const confirm  = document.getElementById('signup-confirm').value;

  if (password !== confirm) {
    showToast('Passwords do not match.', 'error');
    return;
  }

  setLoading('signup-btn', true);
  try {
    const res  = await fetch(`${API}/api/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, full_name: fullName, dob, password }),
    });
    const data = await res.json();

    if (res.ok) {
      showToast(' Account created! Please sign in.', 'success');
      document.getElementById('signup-form').reset();
      const loginEmail = document.getElementById('login-email');
      if (loginEmail) loginEmail.value = email;
      sessionStorage.setItem('finaly_email', email);
      toggleView('login-form');
    } else {
      const msg = Array.isArray(data.detail)
        ? data.detail.map(e => e.msg.replace('Value error, ', '')).join(' • ')
        : (data.detail || 'Signup failed. Check your details.');
      showToast(` ${msg}`, 'error', 7000);
    }
  } catch (err) {
    console.error('Signup network error:', err);
    showToast('️ Cannot reach server. Is the backend running on port 8000?', 'error', 7000);
  } finally {
    setLoading('signup-btn', false);
  }
}

// ═══════════════════════════════════════════════════════════
//  LOG IN
// ═══════════════════════════════════════════════════════════
async function handleLogin(event) {
  event.preventDefault();

  const email    = document.getElementById('login-email').value.trim();
  const password = document.getElementById('login-password').value;

  setLoading('login-btn', true);
  try {
    const res  = await fetch(`${API}/api/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password }),
    });

    // Handle rate-limit response (may or may not be JSON)
    if (res.status === 429) {
      let msg = 'Too many attempts. Please wait 1 minute and try again.';
      try {
        const d = await res.json();
        msg = d.detail || d.error || msg;
      } catch { /* not JSON */ }
      showToast(`⏳ ${msg}`, 'warning', 8000);
      return;
    }

    const data = await res.json();

    if (!res.ok) {
      showToast(` ${data.detail || 'Login failed. Check your credentials.'}`, 'error', 5000);
      return;
    }

    //  Credentials verified — store pre-MFA token
    sessionStorage.setItem('finaly_token', data.access_token);
    sessionStorage.setItem('finaly_email', email);

    if (data.mfa_required) {
      // User already has MFA fully enabled — ask for OTP code
      showToast(' Enter your 6-digit authenticator code.', 'info');
      toggleView('mfa-form');
    } else {
      // First-time setup — call /api/mfa/setup to get QR code
      showToast(' Login successful! Loading MFA setup…', 'success', 3000);
      await triggerMFASetup(data.access_token, email);
    }

  } catch (err) {
    console.error('Login network error:', err);
    showToast('️ Cannot reach server. Is the backend running on port 8000?', 'error', 7000);
  } finally {
    setLoading('login-btn', false);
  }
}

// ═══════════════════════════════════════════════════════════
//  MFA SETUP
// ═══════════════════════════════════════════════════════════
async function triggerMFASetup(token, email) {
  try {
    const res  = await fetch(`${API}/api/mfa/setup`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}` },
    });
    const data = await res.json();

    if (!res.ok) {
      // MFA already fully enabled — ask user to enter OTP
      console.warn('MFA setup response:', data);
      showToast(' MFA already configured. Enter your authenticator code.', 'info', 5000);
      toggleView('mfa-form');
      return;
    }

    //  Got TOTP URI — save to sessionStorage for refresh recovery
    sessionStorage.setItem('mfa_totp_uri', data.totp_uri);
    sessionStorage.setItem('mfa_secret',   data.secret);

    // Save QR base64 in session storage for page refreshes
    if (data.qr_base64) sessionStorage.setItem('mfa_qr_base64', data.qr_base64);

    // Render QR code inline (never opens a new tab)
    renderQrCode(data.totp_uri, data.secret, data.qr_base64);

    // Show the setup form
    toggleView('mfa-setup-form');
    showToast(
      ' Open Google Authenticator or Authy → Add Account → Scan QR code, then enter the 6-digit code below.',
      'info',
      10000
    );

  } catch (err) {
    console.error('MFA setup network error:', err);
    // Fallback: let user try entering OTP in case they have a working session
    showToast('️ MFA setup failed. If you already scanned the QR before, enter your code below.', 'warning', 7000);
    toggleView('mfa-form');
  }
}

// Called when user submits 6-digit code on the SETUP form
async function confirmMFASetup(event) {
  event.preventDefault();
  const code = document.getElementById('setup-mfa-code').value.trim();
  if (code.length !== 6 || !/^\d{6}$/.test(code)) {
    showToast('️ Please enter the 6-digit code from your authenticator app.', 'warning');
    return;
  }
  setLoading('setup-mfa-btn', true);
  await _doMFAVerify(code);
  setLoading('setup-mfa-btn', false);
}

// ═══════════════════════════════════════════════════════════
//  MFA VERIFY (existing MFA users)
// ═══════════════════════════════════════════════════════════
async function verifyMFA(event) {
  event.preventDefault();
  const code = document.getElementById('mfa-code').value.trim();
  if (code.length !== 6 || !/^\d{6}$/.test(code)) {
    showToast('️ Please enter the 6-digit code from your authenticator app.', 'warning');
    return;
  }
  setLoading('mfa-btn', true);
  await _doMFAVerify(code);
  setLoading('mfa-btn', false);
}

// Shared OTP verification logic
async function _doMFAVerify(code) {
  const token = sessionStorage.getItem('finaly_token');
  if (!token) {
    showToast('Session expired. Please log in again.', 'error');
    sessionStorage.clear();
    toggleView('login-form');
    return;
  }

  try {
    const res  = await fetch(`${API}/api/mfa/verify`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`,
      },
      body: JSON.stringify({ totp_code: code }),
    });
    const data = await res.json();

    if (res.ok) {
      //  Verified — upgrade tokens and go to dashboard
      sessionStorage.setItem('finaly_token',   data.access_token);
      sessionStorage.setItem('finaly_refresh',  data.refresh_token);
      // Clear MFA setup temps
      sessionStorage.removeItem('auth_view');
      sessionStorage.removeItem('mfa_totp_uri');
      sessionStorage.removeItem('mfa_secret');

      showToast(' MFA verified! Redirecting to your dashboard…', 'success');
      setTimeout(() => { window.location.href = 'index.html'; }, 1200);
    } else {
      const msg = data.detail || 'Invalid OTP code.';
      showToast(` ${msg} — Check your authenticator app and try again.`, 'error', 6000);
    }
  } catch (err) {
    console.error('MFA verify error:', err);
    showToast('️ Cannot reach server.', 'error');
  }
}