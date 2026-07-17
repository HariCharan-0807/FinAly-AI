/**
 * FinAly AI — dashboard.js  v4.0
 * Handles: auth guard, auto token refresh, API calls,
 *          charts, transactions, budgets, savings, export, chat.
 *
 * API Base URL: read from <meta name="api-url"> in index.html.
 * For local dev:  content="http://127.0.0.1:8000"
 * For Vercel+Railway:  content="https://your-backend.railway.app"
 */

const API = (
  document.querySelector('meta[name="api-url"]')?.getAttribute('content') ||
  'https://web-production-c2931.up.railway.app'
).replace(/\/$/, ''); // strip trailing slash



// ═══════════════════════════════════════════════════════════
//  Utilities
// ═══════════════════════════════════════════════════════════
function showToast(message, type = 'info', duration = 4000) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.className = `toast ${type} show`;
  clearTimeout(toast._timer);
  toast._timer = setTimeout(() => { toast.className = 'toast'; }, duration);
}

function formatCurrency(amount) {
  return '₹' + Math.abs(amount).toLocaleString('en-IN', { maximumFractionDigits: 2 });
}

function formatDate(dateStr) {
  const d = new Date(dateStr);
  return d.toLocaleDateString('en-IN', { day: 'numeric', month: 'short', year: 'numeric' });
}

const CATEGORY_EMOJI = {
  Food: '', Rent: '', Transport: '', Utilities: '',
  Healthcare: '', Entertainment: '', Shopping: '️',
  Education: '', Income: '', Other: '',
};

// Auth header helper
function authHeader() {
  const token = sessionStorage.getItem('finaly_token');
  return token ? { 'Authorization': `Bearer ${token}` } : {};
}

function animateValue(el, end, prefix = '₹', suffix = '') {
  if (!el) return;
  const currStr = (el.textContent || '').replace(/[^0-9.-]+/g, '');
  const start   = currStr ? parseFloat(currStr) : 0;
  if (isNaN(start) || start === end) {
    el.textContent = prefix + end.toLocaleString('en-IN', { maximumFractionDigits: 2 }) + suffix;
    return;
  }
  const duration  = start === 0 ? 1000 : 350; // fast transition on updates
  const startTime = performance.now();

  function update(currentTime) {
    const elapsed  = currentTime - startTime;
    const progress = Math.min(elapsed / duration, 1);
    const eased    = 1 - Math.pow(1 - progress, 3);
    const current  = start + (end - start) * eased;
    el.textContent = prefix + Math.round(current).toLocaleString('en-IN') + suffix;
    if (progress < 1) requestAnimationFrame(update);
    else el.textContent = prefix + end.toLocaleString('en-IN', { maximumFractionDigits: 2 }) + suffix;
  }
  requestAnimationFrame(update);
}

// ═══════════════════════════════════════════════════════════
//  Auth Guard — validate token server-side, don't just check existence
// ═══════════════════════════════════════════════════════════
async function guardAuth() {
  const token = sessionStorage.getItem('finaly_token');
  if (!token) {
    window.location.href = 'login.html';
    return false;
  }

  try {
    const res = await authFetch(`${API}/api/dashboard/summary`, {
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
    });

    if (res.status === 401) {
      // Try to refresh
      const refreshed = await tryRefreshToken();
      if (!refreshed) {
        sessionStorage.clear();
        window.location.href = 'login.html';
        return false;
      }
    }
    return true;
  } catch {
    showToast('Cannot connect to server. Make sure the backend is running.', 'error', 8000);
    return false;
  }
}

async function tryRefreshToken() {
  const refresh = sessionStorage.getItem('finaly_refresh');
  if (!refresh) return false;

  try {
    const res = await fetch(`${API}/api/token/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: refresh }),
    });

    if (res.ok) {
      const data = await res.json();
      sessionStorage.setItem('finaly_token', data.access_token);
      sessionStorage.setItem('finaly_refresh', data.refresh_token);
      return true;
    }
  } catch { /* fall through */ }
  return false;
}

/**
 * Smart fetch wrapper — automatically refreshes expired JWT and retries once.
 * Use this instead of raw fetch() + authHeader() for all authenticated API calls.
 */
async function authFetch(url, options = {}) {
  // Inject current auth header
  options.headers = { ...authHeader(), ...(options.headers || {}) };
  let res = await fetch(url, options);

  if (res.status === 401) {
    const refreshed = await tryRefreshToken();
    if (refreshed) {
      // Update auth header with new token and retry
      options.headers = { ...options.headers, ...authHeader() };
      res = await fetch(url, options);
    } else {
      sessionStorage.clear();
      window.location.href = 'login.html';
      return res;
    }
  }
  return res;
}

function logoutUser() {
  // Call logout API to blacklist the token
  fetch(`${API}/api/logout`, {
    method: 'POST',
    headers: authHeader(),
  }).finally(() => {
    sessionStorage.clear();
    window.location.href = 'login.html';
  });
}


// ═══════════════════════════════════════════════════════════
//  Navigation
// ═══════════════════════════════════════════════════════════
function switchSection(sectionName) {
  const sectionId = `section-${sectionName}`;
  const targetEl  = document.getElementById(sectionId);
  if (!targetEl) return;

  document.querySelectorAll('.section').forEach(s => {
    s.classList.remove('active');
    s.classList.add('hidden');
  });
  document.querySelectorAll('.nav-link').forEach(l => {
    l.classList.toggle('active', l.dataset.section === sectionName);
  });
  targetEl.classList.remove('hidden');
  targetEl.classList.add('active');

  // Load section data on demand
  if (sectionName === 'transactions') loadTransactions();
  if (sectionName === 'budgets')      loadBudgets();
  if (sectionName === 'savings')      loadSavingsGoals();
  if (sectionName === 'bank')         initBankSection();
  if (sectionName === 'export')       initExportSection();
}

function initNav() {
  document.querySelectorAll('.nav-link').forEach(link => {
    link.addEventListener('click', e => {
      e.preventDefault();
      switchSection(link.dataset.section);
      if (history.pushState) {
        history.pushState(null, null, `#section-${link.dataset.section}`);
      }
    });
  });

  // Support browser Back/Forward & URL hash changes
  window.addEventListener('hashchange', () => {
    const h = window.location.hash.replace('#section-', '');
    if (h && document.getElementById(`section-${h}`)) switchSection(h);
  });

  // Check initial URL hash on load (e.g. index.html#section-bank)
  const initialHash = window.location.hash.replace('#section-', '');
  if (initialHash && document.getElementById(`section-${initialHash}`)) {
    switchSection(initialHash);
  }
}


// ═══════════════════════════════════════════════════════════
//  Dashboard Summary
// ═══════════════════════════════════════════════════════════
let categoryBreakdownData = {};
let expenseChart, categoryChart;

async function loadDashboardSummary() {
  try {
    const res = await authFetch(`${API}/api/dashboard/summary`, {
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
    });

    if (!res.ok) return;
    const data = await res.json();

    // Animate metric cards
    const balEl = document.getElementById('total-balance');
    const incEl = document.getElementById('monthly-income');
    const expEl = document.getElementById('monthly-expenses');

    animateValue(balEl, data.total_balance);
    animateValue(incEl, data.monthly_income);
    animateValue(expEl, data.monthly_expenses);
    document.getElementById('savings-pct').textContent = data.savings_progress_pct.toFixed(1) + '%';

    // Animate savings bar
    setTimeout(() => {
      document.getElementById('savings-bar').style.width = data.savings_progress_pct + '%';
    }, 100);

    categoryBreakdownData = data.category_breakdown;
    updateCategoryChart(data.category_breakdown);

    // ── Populate chart data from real transactions ──
    if (data.daily_expenses) {
      CHART_DATA.daily.data = data.daily_expenses;
    }
    if (data.weekly_expenses) {
      CHART_DATA.weekly.data = data.weekly_expenses;
    }
    if (data.monthly_expense_totals) {
      CHART_DATA.monthly.data = data.monthly_expense_totals;
    }

    // Generate proper month labels for last 6 months
    const now = new Date();
    const monthNames = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    const monthLabels = [];
    for (let i = 5; i >= 0; i--) {
      let m = now.getMonth() - i;
      if (m < 0) m += 12;
      monthLabels.push(monthNames[m]);
    }
    CHART_DATA.monthly.labels = monthLabels;

    // Refresh the active chart view
    const activeBtn = document.querySelector('.toggle-btn.active');
    const activeTimeframe = activeBtn ? (activeBtn.textContent.toLowerCase().includes('daily') ? 'daily' : activeBtn.textContent.toLowerCase().includes('monthly') ? 'monthly' : 'weekly') : 'weekly';
    switchChart({ target: activeBtn || {} }, activeTimeframe);

    // Timestamp
    document.getElementById('last-updated').textContent =
      'Updated ' + now.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' });

    // Date heading
    document.getElementById('current-date').textContent =
      now.toLocaleDateString('en-IN', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

    // User badge
    const fullName = data.full_name || sessionStorage.getItem('finaly_name') || '';
    const email = data.email || sessionStorage.getItem('finaly_email') || '';
    if (fullName) {
      sessionStorage.setItem('finaly_name', fullName);
      document.getElementById('user-name-badge').textContent = fullName;
    } else {
      document.getElementById('user-name-badge').textContent = email.split('@')[0] || 'User';
    }
    if (data.email) sessionStorage.setItem('finaly_email', data.email);

    // Show income prompt if not set
    if (data.monthly_income === 0) {
      const incomeCard = document.getElementById('card-income');
      if (incomeCard && !incomeCard.querySelector('.set-income-link')) {
        const link = document.createElement('a');
        link.href = '#';
        link.className = 'set-income-link';
        link.textContent = 'Set your monthly income →';
        link.style.cssText = 'font-size:12px;color:#4f46e5;font-weight:600;text-decoration:none;display:block;margin-top:6px;';
        link.onclick = (e) => { e.preventDefault(); promptSetMonthlyIncome(); };
        incomeCard.appendChild(link);
      }
    }

    // Render dynamic AI Savings Insights
    const insightsGrid = document.getElementById('insights-grid');
    if (insightsGrid && data.ai_insights && data.ai_insights.length > 0) {
      insightsGrid.innerHTML = data.ai_insights.map(item => `
        <div class="insight-card ${item.highlight ? 'highlight' : ''}">
          <div class="insight-text">
            <h4>${item.title || 'AI Insight'}</h4>
            <p>${item.text || ''}</p>
          </div>
        </div>`).join('');
    }

  } catch (e) {
    console.error('Dashboard summary failed:', e);
  }
}

async function loadMLInsights() {
  const spendEl = document.getElementById('ml-predicted-spend');
  const anomEl  = document.getElementById('ml-anomaly-list');

  try {
    const res = await authFetch(`${API}/api/ml/insights`, {
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
    });

    // Handle non-OK responses (actual server errors)
    if (!res.ok) {
      const errJson = await res.json().catch(() => ({}));
      // 401 = not logged in yet, don't show red error
      if (res.status === 401) return;
      if (spendEl) spendEl.innerHTML = '<span style="color:#ef4444;font-size:13px;">⚠️ Could not load forecast. Please try again.</span>';
      if (anomEl)  anomEl.innerHTML  = '<p style="font-size:13px;color:#ef4444;">⚠️ Could not scan transactions.</p>';
      return;
    }

    const data = await res.json();

    // ── Handle insufficient data (no transactions yet) ──────────────
    if (data.model_status === 'insufficient_data' || !data.forecast) {
      if (spendEl) spendEl.innerHTML = '<span style="font-size:13px;color:#64748b;">➕ Add expense transactions to see your forecast.</span>';
      if (anomEl)  anomEl.innerHTML  = '<p style="font-size:13px;color:#64748b;">Add expense transactions to enable anomaly scanning.</p>';
      return;
    }

    // ── Render Expenditure Forecast ─────────────────────────────────
    if (data.forecast && spendEl) {
      const estimated  = (data.forecast.predicted_next_30d_expenses || 0).toLocaleString('en-IN', {minimumFractionDigits: 2, maximumFractionDigits: 2});
      const actual     = (data.forecast.last_30d_actual || 0).toLocaleString('en-IN', {minimumFractionDigits: 2, maximumFractionDigits: 2});
      const trend      = data.forecast.expenditure_trend || 'stable';
      const trendIcon  = trend === 'increasing' ? '📈 Trending up' : trend === 'decreasing' ? '📉 Trending down' : '➡️ Stable';
      const trendColor = trend === 'increasing' ? '#ef4444' : trend === 'decreasing' ? '#10b981' : '#f59e0b';

      spendEl.innerHTML = `
        <span style="font-size:22px;font-weight:800;color:#4f46e5;">₹${estimated}</span>
        <div style="font-size:11px;color:#64748b;margin-top:4px;">Last 30 days actual: <b>₹${actual}</b></div>
        <div style="font-size:11px;margin-top:3px;color:${trendColor};">${trendIcon}</div>`;
    }

    // ── Render Anomaly Radar ────────────────────────────────────────
    if (anomEl) {
      if (data.anomalies && data.anomalies.length > 0) {
        const seen = new Map();
        for (const a of data.anomalies) {
          const key = (a.description || '').trim().toLowerCase();
          if (!seen.has(key)) {
            seen.set(key, { ...a, count: 1 });
          } else {
            const existing = seen.get(key);
            existing.count++;
            if (a.amount > existing.amount) existing.amount = a.amount;
          }
        }
        anomEl.innerHTML = [...seen.values()].map(a => `
          <div style="font-size:12px; background:rgba(239,68,68,0.1); padding:6px 8px; border-radius:6px; margin-top:6px; border-left:3px solid #ef4444; display:flex; justify-content:space-between; align-items:flex-start;">
            <div>
              <strong>${a.description}</strong>${ a.count > 1 ? ` <span style="font-size:10px;background:#ef4444;color:#fff;border-radius:10px;padding:1px 6px;margin-left:4px;">${a.count}×</span>` : '' } <br>
              <span style="color:#ef4444; font-size:11px;">⚠️ Unusual spending detected</span>
            </div>
            <span style="font-size:13px;font-weight:700;color:#1e293b;white-space:nowrap;margin-left:8px;">₹${a.amount.toLocaleString('en-IN')}</span>
          </div>
        `).join('');
      } else {
        anomEl.innerHTML = '<p style="font-size:13px; color:#10b981; margin-top:6px;">✅ No unusual spending activity detected.</p>';
      }
    }

  } catch (err) {
    console.error('ML fetch failed:', err);
    if (spendEl) spendEl.innerHTML = '<span style="font-size:13px;color:#64748b;">⚠️ Forecast unavailable — check your connection.</span>';
    if (anomEl)  anomEl.innerHTML  = '<p style="font-size:13px;color:#64748b;">⚠️ Anomaly scan unavailable.</p>';
  }
}



// ═══════════════════════════════════════════════════════════
//  Charts
// ═══════════════════════════════════════════════════════════
const CHART_OPTS = {
  responsive: true,
  maintainAspectRatio: false,
  plugins: { legend: { display: false } },
};

const PALETTE = [
  '#3b82f6', '#8b5cf6', '#06b6d4', '#22c55e',
  '#f97316', '#ef4444', '#f59e0b', '#10b981', '#6366f1', '#84cc16',
];

function initExpenseChart() {
  const ctx = document.getElementById('expenseChart').getContext('2d');
  expenseChart = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: ['Week 1', 'Week 2', 'Week 3', 'Week 4'],
      datasets: [{
        label: 'Expenses (₹)',
        data: [0, 0, 0, 0],
        backgroundColor: 'rgba(79, 70, 229, 0.6)',
        borderColor: '#4f46e5',
        borderWidth: 1,
        borderRadius: 6,
        hoverBackgroundColor: '#4338ca',
      }],
    },
    options: {
      ...CHART_OPTS,
      scales: {
        x: { grid: { display: false }, ticks: { color: '#94a3b8' } },
        y: { beginAtZero: true, grid: { color: '#f1f5f9' }, ticks: { color: '#94a3b8' } },
      },
    },
  });
  // Show "No Data" overlay since there's no real data yet
  showChartNoData('expenseChart');
}

function initCategoryChart() {
  const ctx = document.getElementById('categoryChart').getContext('2d');
  categoryChart = new Chart(ctx, {
    type: 'doughnut',
    data: {
      labels: ['No Data'],
      datasets: [{
        data: [1],
        backgroundColor: ['rgba(255,255,255,0.1)'],
        borderWidth: 0,
        hoverOffset: 8,
      }],
    },
    options: {
      ...CHART_OPTS,
      plugins: {
        legend: {
          display: true,
          position: 'bottom',
          labels: {
            color: '#94a3b8',
            font: { family: 'Inter', size: 11 },
            padding: 12,
            boxWidth: 12,
          },
        },
      },
      cutout: '68%',
    },
  });
}

function updateCategoryChart(breakdown) {
  const labels = Object.keys(breakdown);
  const values = Object.values(breakdown);

  if (!labels.length) return;

  categoryChart.data.labels = labels;
  categoryChart.data.datasets[0].data = values;
  categoryChart.data.datasets[0].backgroundColor = PALETTE.slice(0, labels.length);
  categoryChart.update('active');
}

// Chart data is populated from real transactions via loadDashboardSummary
const CHART_DATA = {
  daily:   { labels: ['Mon','Tue','Wed','Thu','Fri','Sat','Sun'], data: [0, 0, 0, 0, 0, 0, 0] },
  weekly:  { labels: ['Week 1','Week 2','Week 3','Week 4'],       data: [0, 0, 0, 0] },
  monthly: { labels: ['Jan','Feb','Mar','Apr','May','Jun'],        data: [0, 0, 0, 0, 0, 0] },
};

function showChartNoData(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const wrap = canvas.closest('.chart-wrap');
  if (!wrap) return;
  // Remove existing overlay if any
  const existing = wrap.querySelector('.chart-no-data');
  if (existing) existing.remove();
  // Add overlay
  const overlay = document.createElement('div');
  overlay.className = 'chart-no-data';
  overlay.innerHTML = '<div class="chart-no-data-icon"></div><span>No data</span>';
  overlay.style.position = 'absolute';
  overlay.style.inset = '0';
  overlay.style.zIndex = '2';
  overlay.style.background = 'rgba(255,255,255,0.85)';
  overlay.style.borderRadius = '8px';
  wrap.style.position = 'relative';
  wrap.appendChild(overlay);
}

function hideChartNoData(canvasId) {
  const canvas = document.getElementById(canvasId);
  if (!canvas) return;
  const wrap = canvas.closest('.chart-wrap');
  if (!wrap) return;
  const overlay = wrap.querySelector('.chart-no-data');
  if (overlay) overlay.remove();
}

function switchChart(event, timeframe) {
  if (!expenseChart) return;
  expenseChart.data.labels = CHART_DATA[timeframe].labels;
  expenseChart.data.datasets[0].data = CHART_DATA[timeframe].data;
  expenseChart.update();
  document.querySelectorAll('.toggle-btn').forEach(b => b.classList.remove('active'));
  if (event.target) event.target.classList.add('active');
  // Show/hide no-data overlay
  const hasData = CHART_DATA[timeframe].data.some(v => v > 0);
  if (hasData) {
    hideChartNoData('expenseChart');
  } else {
    showChartNoData('expenseChart');
  }
}


// ═══════════════════════════════════════════════════════════
//  Transactions
// ═══════════════════════════════════════════════════════════
async function loadTransactions() {
  const list = document.getElementById('txn-list');
  list.innerHTML = '<p class="empty-state">Loading…</p>';

  try {
    const res = await authFetch(`${API}/api/transactions`, { headers: authHeader() });
    if (!res.ok) throw new Error();
    const txns = await res.json();

    if (!txns.length) {
      list.innerHTML = '<p class="empty-state">No transactions yet. Add your first one above!</p>';
      return;
    }

    list.innerHTML = '';
    txns.forEach(t => list.appendChild(buildTxnItem(t)));
  } catch {
    list.innerHTML = '<p class="empty-state">Failed to load transactions.</p>';
  }
}

function buildTxnItem(t) {
  const div = document.createElement('div');
  div.className = 'txn-item';
  div.id = `txn-${t.id}`;
  const isIncome = t.transaction_type === 'Income';
  div.innerHTML = `
    <div class="txn-left">
      <span class="txn-emoji">${CATEGORY_EMOJI[t.category] || ''}</span>
      <div class="txn-info">
        <div class="txn-category">${t.category}</div>
        <div class="txn-date">${formatDate(t.date)}</div>
        ${t.description ? `<div class="txn-desc">${t.description}</div>` : ''}
      </div>
    </div>
    <div class="txn-right">
      <span class="txn-amount ${isIncome ? 'income' : 'expense'}">
        ${isIncome ? '+' : '-'}${formatCurrency(t.amount)}
      </span>
      <button class="txn-delete" onclick="deleteTransaction(${t.id})" title="Delete" aria-label="Delete transaction"></button>
    </div>`;
  return div;
}

async function addTransaction(event) {
  event.preventDefault();
  const btn = document.getElementById('txn-submit-btn');
  btn.disabled = true;
  btn.textContent = 'Saving…';

  const payload = {
    transaction_type: document.getElementById('txn-type').value,
    amount: parseFloat(document.getElementById('txn-amount').value),
    category: document.getElementById('txn-category').value,
    description: document.getElementById('txn-desc').value || null,
  };

  try {
    const res = await authFetch(`${API}/api/transactions`, {
      method: 'POST',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      const newTxn = await res.json();
      const list = document.getElementById('txn-list');
      const empty = list.querySelector('.empty-state');
      if (empty) empty.remove();
      list.prepend(buildTxnItem(newTxn));
      document.getElementById('txn-form').reset();
      showToast('Transaction added!', 'success');
      loadDashboardSummary();
    } else {
      const data = await res.json();
      showToast(`Error: ${data.detail}`, 'error');
    }
  } catch {
    showToast('Failed to add transaction.', 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Add Transaction';
  }
}

async function deleteTransaction(id) {
  try {
    const res = await authFetch(`${API}/api/transactions/${id}`, {
      method: 'DELETE',
      headers: authHeader(),
    });

    if (res.status === 204) {
      const el = document.getElementById(`txn-${id}`);
      if (el) el.remove();
      showToast('Transaction deleted.', 'warning');
      loadDashboardSummary();
    }
  } catch {
    showToast('Failed to delete transaction.', 'error');
  }
}


// ═══════════════════════════════════════════════════════════
//  Budgets
// ═══════════════════════════════════════════════════════════
async function loadBudgets() {
  const list = document.getElementById('budget-list');
  list.innerHTML = '<p class="empty-state">Loading…</p>';

  try {
    // Fetch fresh summary so categoryBreakdownData reflects current expenses
    const summaryRes = await authFetch(`${API}/api/dashboard/summary`, { headers: authHeader() });
    if (summaryRes.ok) {
      const summaryData = await summaryRes.json();
      categoryBreakdownData = summaryData.category_breakdown;
    }

    const res = await authFetch(`${API}/api/budgets`, { headers: authHeader() });
    if (!res.ok) throw new Error();
    const budgets = await res.json();

    if (!budgets.length) {
      list.innerHTML = '<p class="empty-state">No budgets yet. Create one above!</p>';
      return;
    }

    const monthNames = ['','Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
    list.innerHTML = '';

    budgets.forEach(b => {
      const spent = categoryBreakdownData[b.category] || 0;
      const pct = b.monthly_limit > 0 ? Math.min((spent / b.monthly_limit) * 100, 100) : 0;
      const isOver = pct >= 100;
      const isNear = pct >= 80 && pct < 100;
      const barColor = isOver ? '#dc2626' : isNear ? '#d97706' : '#4f46e5';

      const div = document.createElement('div');
      div.className = 'budget-item';
      div.id = `budget-${b.id}`;

      const header = document.createElement('div');
      header.className = 'budget-item-header';

      const catSpan = document.createElement('span');
      catSpan.className = 'category';
      catSpan.textContent = b.category;

      const rightGroup = document.createElement('div');
      rightGroup.style.cssText = 'display:flex;align-items:center;gap:10px;flex-wrap:wrap;';

      const limitSpan = document.createElement('span');
      limitSpan.className = 'limit';
      limitSpan.textContent = `${monthNames[b.month]} ${b.year} · Limit: ${formatCurrency(b.monthly_limit)}`;

      const editBtn = document.createElement('button');
      editBtn.className = 'budget-edit-btn';
      editBtn.textContent = 'Edit';
      editBtn.onclick = () => openEditBudget(b.id, b.category, b.monthly_limit, b.month, b.year);

      const delBtn = document.createElement('button');
      delBtn.className = 'budget-delete-btn';
      delBtn.textContent = 'Delete';
      delBtn.onclick = () => deleteBudget(b.id);

      rightGroup.appendChild(limitSpan);
      rightGroup.appendChild(editBtn);
      rightGroup.appendChild(delBtn);
      header.appendChild(catSpan);
      header.appendChild(rightGroup);

      const progressRow = document.createElement('div');
      progressRow.className = 'budget-progress-row';
      progressRow.innerHTML = `<span style="color:${barColor};font-size:12px;font-weight:600;">Spent: ${formatCurrency(spent)}</span><span style="color:${barColor};font-size:12px;font-weight:700;">${pct.toFixed(0)}%</span>`;

      const barBg = document.createElement('div');
      barBg.className = 'budget-bar-bg';
      const barFill = document.createElement('div');
      barFill.className = 'budget-bar-fill';
      barFill.style.cssText = `width:0%;background:${barColor};`;
      barBg.appendChild(barFill);

      div.appendChild(header);
      div.appendChild(progressRow);
      div.appendChild(barBg);

      if (isOver) {
        const warn = document.createElement('p');
        warn.className = 'budget-warning';
        warn.textContent = 'Over budget!';
        div.appendChild(warn);
      } else if (isNear) {
        const warn = document.createElement('p');
        warn.className = 'budget-warning';
        warn.style.color = '#d97706';
        warn.textContent = 'Near limit — slow down spending';
        div.appendChild(warn);
      }

      list.appendChild(div);
      setTimeout(() => { barFill.style.width = pct + '%'; }, 80);
    });

  } catch (e) {
    console.error('Budget load error:', e);
    list.innerHTML = '<p class="empty-state">Failed to load budgets.</p>';
  }
}


async function addBudget(event) {
  event.preventDefault();

  const payload = {
    category: document.getElementById('budget-category').value,
    monthly_limit: parseFloat(document.getElementById('budget-limit').value),
    month: parseInt(document.getElementById('budget-month').value),
    year: parseInt(document.getElementById('budget-year').value),
  };

  try {
    const res = await authFetch(`${API}/api/budgets`, {
      method: 'POST',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      showToast('Budget created!', 'success');
      document.getElementById('budget-form').reset();
      document.getElementById('budget-year').value = new Date().getFullYear();
      loadBudgets();
    } else {
      const data = await res.json();
      showToast(`Error: ${data.detail}`, 'error');
    }
  } catch {
    showToast('Failed to create budget.', 'error');
  }
}

async function deleteBudget(id) {
  if (!confirm('Are you sure you want to delete this budget?')) return;
  try {
    const res = await authFetch(`${API}/api/budgets/${id}`, {
      method: 'DELETE',
      headers: authHeader(),
    });
    if (res.status === 204) {
      document.getElementById(`budget-${id}`)?.remove();
      showToast('Budget deleted.', 'warning');
      const list = document.getElementById('budget-list');
      if (!list.querySelector('.budget-item')) {
        list.innerHTML = '<p class="empty-state">No budgets yet. Create one above!</p>';
      }
    }
  } catch {
    showToast('Failed to delete budget.', 'error');
  }
}

function openEditBudget(id, category, limit, month, year) {
  document.getElementById('budget-edit-modal')?.remove();

  const allMonths = ['January','February','March','April','May','June','July','August','September','October','November','December'];
  const monthOpts = allMonths.map((m, i) =>
    `<option value="${i + 1}" ${month === i + 1 ? 'selected' : ''}>${m}</option>`
  ).join('');
  const catOpts = ['Food','Rent','Transport','Utilities','Healthcare','Entertainment','Shopping','Education','Other']
    .map(c => `<option value="${c}" ${category === c ? 'selected' : ''}>${c}</option>`).join('');

  const modal = document.createElement('div');
  modal.id = 'budget-edit-modal';
  modal.style.cssText = 'position:fixed;inset:0;z-index:1000;display:flex;align-items:center;justify-content:center;';
  modal.innerHTML = `
    <div style="position:absolute;inset:0;background:rgba(0,0,0,0.35);" onclick="document.getElementById('budget-edit-modal').remove()"></div>
    <div style="position:relative;background:#fff;border-radius:14px;padding:28px;width:100%;max-width:480px;box-shadow:0 8px 32px rgba(0,0,0,0.12);border:1px solid #e2e8f0;">
      <h3 style="font-size:17px;font-weight:700;color:#1e293b;margin-bottom:20px;">Edit Budget</h3>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:20px;">
        <div class="input-group">
          <label>Category</label>
          <select id="edit-budget-category">${catOpts}</select>
        </div>
        <div class="input-group">
          <label>Monthly Limit (₹)</label>
          <input type="number" id="edit-budget-limit" value="${limit}" min="1" step="1">
        </div>
        <div class="input-group">
          <label>Month</label>
          <select id="edit-budget-month">${monthOpts}</select>
        </div>
        <div class="input-group">
          <label>Year</label>
          <input type="number" id="edit-budget-year" value="${year}" min="2020" max="2100">
        </div>
      </div>
      <div style="display:flex;gap:10px;">
        <button class="primary-btn-sm" onclick="submitEditBudget(${id})" style="flex:1;">Save Changes</button>
        <button onclick="document.getElementById('budget-edit-modal').remove()" style="flex:1;padding:10px 16px;border:1.5px solid #e2e8f0;border-radius:8px;background:#f8fafc;cursor:pointer;font-family:Inter,sans-serif;font-size:14px;font-weight:600;color:#475569;">Cancel</button>
      </div>
    </div>`;
  document.body.appendChild(modal);
}

async function submitEditBudget(id) {
  const payload = {
    category: document.getElementById('edit-budget-category').value,
    monthly_limit: parseFloat(document.getElementById('edit-budget-limit').value),
    month: parseInt(document.getElementById('edit-budget-month').value),
    year: parseInt(document.getElementById('edit-budget-year').value),
  };

  if (!payload.monthly_limit || payload.monthly_limit <= 0) {
    showToast('Please enter a valid limit amount.', 'error');
    return;
  }

  try {
    const res = await authFetch(`${API}/api/budgets/${id}`, {
      method: 'PUT',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      document.getElementById('budget-edit-modal')?.remove();
      showToast('Budget updated!', 'success');
      loadBudgets();
    } else {
      const data = await res.json();
      showToast(`Error: ${data.detail}`, 'error');
    }
  } catch {
    showToast('Failed to update budget.', 'error');
  }
}


// ═══════════════════════════════════════════════════════════
//  Savings Goals
// ═══════════════════════════════════════════════════════════
async function loadSavingsGoals() {
  const list = document.getElementById('savings-list');
  list.innerHTML = '<p class="empty-state">Loading…</p>';

  try {
    const res = await authFetch(`${API}/api/savings`, { headers: authHeader() });
    if (!res.ok) throw new Error();
    const goals = await res.json();

    if (!goals.length) {
      list.innerHTML = '<p class="empty-state">No savings goals yet. Create your first one above! </p>';
      return;
    }

    list.innerHTML = '';
    list.className = 'savings-list';
    goals.forEach(g => {
      const pct = g.target_amount > 0
        ? Math.min((g.current_amount / g.target_amount) * 100, 100)
        : 0;
      const isComplete = pct >= 100;
      const card = document.createElement('div');
      card.className = `savings-card${isComplete ? ' savings-card--complete' : ''}`;
      card.id = `savings-card-${g.id}`;
      card.innerHTML = `
        <div class="savings-card-header">
          <span class="savings-card-name"> ${g.name}</span>
          <div class="savings-card-actions">
            <button class="savings-add-btn" onclick="openAddMoneySavings(${g.id}, '${g.name.replace(/'/g,"\\'")}', ${g.current_amount}, ${g.target_amount})" title="Add money">
              + Add Money
            </button>
            <button class="savings-edit-btn" onclick="openEditSavingsGoal(${g.id}, '${g.name.replace(/'/g,"\\'")}', ${g.target_amount}, ${g.current_amount}, '${g.deadline || ''}')" title="Edit goal">
              ️ Edit
            </button>
            <button class="savings-delete-btn" onclick="deleteSavingsGoal(${g.id})" title="Delete goal">
              Delete
            </button>
          </div>
        </div>
        <div class="savings-pct${isComplete ? ' savings-pct--done' : ''}">${isComplete ? ' ' : ''}${pct.toFixed(1)}%</div>
        <div class="savings-amounts">
          <span class="savings-current">${formatCurrency(g.current_amount)} saved</span>
          <span class="savings-sep">of</span>
          <span class="savings-target">${formatCurrency(g.target_amount)} goal</span>
        </div>
        <div class="savings-bar-bg">
          <div class="savings-bar-fill${isComplete ? ' savings-bar-fill--done' : ''}" style="width: 0%"></div>
        </div>
        <div class="savings-remaining">
          ${isComplete
            ? ' Goal reached! Congratulations!'
            : `${formatCurrency(g.target_amount - g.current_amount)} remaining`}
        </div>
        ${g.deadline ? `<div class="savings-deadline"> Deadline: ${formatDate(g.deadline)}</div>` : ''}`;
      list.appendChild(card);
      setTimeout(() => {
        card.querySelector('.savings-bar-fill').style.width = pct + '%';
      }, 100);
    });
  } catch {
    list.innerHTML = '<p class="empty-state">Failed to load savings goals.</p>';
  }
}

async function addSavingsGoal(event) {
  event.preventDefault();

  const payload = {
    name: document.getElementById('goal-name').value.trim(),
    target_amount: parseFloat(document.getElementById('goal-target').value),
    current_amount: parseFloat(document.getElementById('goal-current').value) || 0,
    deadline: document.getElementById('goal-deadline').value || null,
  };

  try {
    const res = await authFetch(`${API}/api/savings`, {
      method: 'POST',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });

    if (res.ok) {
      showToast('Savings goal added! ', 'success');
      document.getElementById('savings-form').reset();
      loadSavingsGoals();
      loadDashboardSummary();
    } else {
      const data = await res.json();
      showToast(`Error: ${data.detail}`, 'error');
    }
  } catch {
    showToast('Failed to add savings goal.', 'error');
  }
}

// ── Add Money shortcut modal ─────────────────────────────────
function openAddMoneySavings(id, name, current, target) {
  const remaining = Math.max(0, target - current);
  _openSavingsModal({
    title: ` Add Money — ${name}`,
    fields: `
      <div class="savings-modal-info">
        <span>Currently saved: <strong>${formatCurrency(current)}</strong></span>
        <span>Remaining: <strong>${formatCurrency(remaining)}</strong></span>
      </div>
      <div class="input-group">
        <label>Amount to Add (₹)</label>
        <input type="number" id="sm-deposit" placeholder="e.g. 5000" min="0.01" step="0.01" autofocus>
      </div>`,
    onSubmit: async () => {
      const deposit = parseFloat(document.getElementById('sm-deposit').value);
      if (!deposit || deposit <= 0) { showToast('Enter a valid amount.', 'error'); return false; }
      const newCurrent = parseFloat((current + deposit).toFixed(2));
      // Fetch the latest goal data to get other fields
      const res = await authFetch(`${API}/api/savings`, { headers: authHeader() });
      const goals = await res.json();
      const g = goals.find(x => x.id === id);
      if (!g) { showToast('Goal not found.', 'error'); return false; }
      return _saveSavingsGoal(id, { name: g.name, target_amount: g.target_amount, current_amount: newCurrent, deadline: g.deadline || null });
    }
  });
}

// ── Full Edit modal ───────────────────────────────────────────
function openEditSavingsGoal(id, name, target, current, deadline) {
  _openSavingsModal({
    title: '️ Edit Savings Goal',
    fields: `
      <div class="input-group">
        <label>Goal Name</label>
        <input type="text" id="sm-name" value="${name}" maxlength="100">
      </div>
      <div class="input-group">
        <label>Target Amount (₹)</label>
        <input type="number" id="sm-target" value="${target}" min="1" step="0.01">
      </div>
      <div class="input-group">
        <label>Current Savings (₹)</label>
        <input type="number" id="sm-current" value="${current}" min="0" step="0.01">
      </div>
      <div class="input-group">
        <label>Deadline (optional)</label>
        <input type="date" id="sm-deadline" value="${deadline}">
      </div>`,
    onSubmit: async () => {
      const name    = document.getElementById('sm-name').value.trim();
      const target  = parseFloat(document.getElementById('sm-target').value);
      const current = parseFloat(document.getElementById('sm-current').value) || 0;
      const dl      = document.getElementById('sm-deadline').value || null;
      if (!name) { showToast('Please enter a goal name.', 'error'); return false; }
      if (!target || target <= 0) { showToast('Please enter a valid target amount.', 'error'); return false; }
      return _saveSavingsGoal(id, { name, target_amount: target, current_amount: current, deadline: dl });
    }
  });
}

async function _saveSavingsGoal(id, payload) {
  try {
    const res = await authFetch(`${API}/api/savings/${id}`, {
      method: 'PUT',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      document.getElementById('savings-modal')?.remove();
      showToast('Savings goal updated! ', 'success');
      loadSavingsGoals();
      loadDashboardSummary();
      return true;
    } else {
      const data = await res.json();
      showToast(`Error: ${data.detail}`, 'error');
      return false;
    }
  } catch {
    showToast('Failed to update savings goal.', 'error');
    return false;
  }
}

async function deleteSavingsGoal(id) {
  if (!confirm('Are you sure you want to delete this savings goal? This cannot be undone.')) return;
  try {
    const res = await authFetch(`${API}/api/savings/${id}`, {
      method: 'DELETE',
      headers: authHeader(),
    });
    if (res.status === 204) {
      document.getElementById(`savings-card-${id}`)?.remove();
      showToast('Savings goal deleted.', 'warning');
      const list = document.getElementById('savings-list');
      if (!list.querySelector('.savings-card')) {
        list.innerHTML = '<p class="empty-state">No savings goals yet. Create your first one above! </p>';
      }
      loadDashboardSummary();
    }
  } catch {
    showToast('Failed to delete savings goal.', 'error');
  }
}

// ── Generic savings modal builder ─────────────────────────────
function _openSavingsModal({ title, fields, onSubmit }) {
  document.getElementById('savings-modal')?.remove();
  const modal = document.createElement('div');
  modal.id = 'savings-modal';
  modal.className = 'savings-modal-overlay';
  modal.innerHTML = `
    <div class="savings-modal-backdrop" onclick="document.getElementById('savings-modal').remove()"></div>
    <div class="savings-modal-box">
      <div class="savings-modal-header">
        <h3>${title}</h3>
        <button class="savings-modal-close" onclick="document.getElementById('savings-modal').remove()"></button>
      </div>
      <div class="savings-modal-body">
        ${fields}
      </div>
      <div class="savings-modal-footer">
        <button class="primary-btn-sm" id="sm-save-btn" onclick="_handleSavingsModalSubmit()">Save Changes</button>
        <button class="savings-modal-cancel" onclick="document.getElementById('savings-modal').remove()">Cancel</button>
      </div>
    </div>`;
  modal.dataset.onsubmit = ''; // store via closure
  document.body.appendChild(modal);
  // Store the onSubmit callback
  modal._onSubmit = onSubmit;
  // Focus first input
  setTimeout(() => modal.querySelector('input')?.focus(), 80);
}

async function _handleSavingsModalSubmit() {
  const modal = document.getElementById('savings-modal');
  if (!modal) return;
  const btn = document.getElementById('sm-save-btn');
  btn.disabled = true;
  btn.textContent = 'Saving…';
  const result = await modal._onSubmit();
  if (!result) {
    btn.disabled = false;
    btn.textContent = 'Save Changes';
  }
}




// ═══════════════════════════════════════════════════════════
// ═══════════════════════════════════════════════════════════
//  AI Chat — Conversational Customer Support
// ═══════════════════════════════════════════════════════════

/**
 * Render lightweight markdown-like formatting to safe HTML.
 * Handles: **bold**, bullet lines (•), \n line breaks, *italic*.
 */
function renderMarkdown(text) {
  return text
    // Escape HTML to prevent XSS
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    // Bold: **text**
    .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
    // Italic: *text*
    .replace(/\*([^*\n]+?)\*/g, '<em>$1</em>')
    // Bullet points: lines starting with •
    .replace(/(^|\n)(• .+)/g, '$1<span class="chat-bullet">$2</span>')
    // Line breaks
    .replace(/\n/g, '<br>');
}

/**
 * Append a message bubble into the chat display.
 * @param {'bot'|'user'} role
 * @param {string} text  Raw text content (markdown supported for bot)
 * @param {boolean} withTypewriter  Animate bot messages letter by letter
 */
function appendBubble(role, text, withTypewriter = false) {
  const display = document.getElementById('chat-display');

  const wrapper = document.createElement('div');
  wrapper.className = `chat-message-row ${role}-row`;

  if (role === 'bot') {
    // Avatar
    const avatar = document.createElement('div');
    avatar.className = 'chat-avatar bot-avatar';
    avatar.textContent = '';
    wrapper.appendChild(avatar);
  }

  const bubble = document.createElement('div');
  bubble.className = `chat-bubble ${role === 'bot' ? 'bot-bubble' : 'user-bubble'}`;

  wrapper.appendChild(bubble);

  if (role === 'user') {
    const avatar = document.createElement('div');
    avatar.className = 'chat-avatar user-avatar';
    const fullName = sessionStorage.getItem('finaly_name') || '';
    const email = sessionStorage.getItem('finaly_email') || '';
    avatar.textContent = (fullName[0] || email[0] || 'U').toUpperCase();
    wrapper.appendChild(avatar);
    bubble.textContent = text;
    display.appendChild(wrapper);
  } else if (withTypewriter) {
    display.appendChild(wrapper);
    const html = renderMarkdown(text);
    // Strip HTML for typewriter, then reveal full HTML at end
    const plainChars = text.split('');
    let i = 0;
    bubble.innerHTML = '';
    const interval = setInterval(() => {
      i += 2; // speed: 2 chars per tick
      // Show partial plain text during typing
      bubble.textContent = plainChars.slice(0, i).join('');
      display.scrollTop = display.scrollHeight;
      if (i >= plainChars.length) {
        clearInterval(interval);
        // Replace with rich formatted HTML once done
        bubble.innerHTML = html;
        display.scrollTop = display.scrollHeight;
        // Re-enable send button after typewriter done
        const btn = document.getElementById('chat-send-btn');
        const input = document.getElementById('chat-input');
        if (btn) { btn.disabled = false; btn.textContent = 'Send '; }
        if (input) { input.disabled = false; input.focus(); }
      }
    }, 18);
  } else {
    bubble.innerHTML = renderMarkdown(text);
    display.appendChild(wrapper);
  }

  display.scrollTop = display.scrollHeight;
  return bubble;
}

async function sendMessage() {
  const input   = document.getElementById('chat-input');
  const sendBtn = document.getElementById('chat-send-btn');
  const display = document.getElementById('chat-display');
  const text    = input.value.trim();
  if (!text) return;

  // Disable input while waiting
  input.value = '';
  input.disabled = true;
  sendBtn.disabled = true;
  sendBtn.textContent = '...';

  // User bubble
  appendBubble('user', text);

  // Typing indicator
  const typingWrapper = document.createElement('div');
  typingWrapper.className = 'chat-message-row bot-row';
  const typingAvatar = document.createElement('div');
  typingAvatar.className = 'chat-avatar bot-avatar';
  typingAvatar.textContent = '';
  const typingBubble = document.createElement('div');
  typingBubble.className = 'chat-bubble bot-bubble typing-bubble';
  typingBubble.innerHTML = '<div class="typing-dot"></div><div class="typing-dot"></div><div class="typing-dot"></div>';
  typingWrapper.appendChild(typingAvatar);
  typingWrapper.appendChild(typingBubble);
  display.appendChild(typingWrapper);
  display.scrollTop = display.scrollHeight;

  try {
    const res  = await authFetch(`${API}/api/chat`, {
      method: 'POST',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: text }),
    });
    const data = await res.json();
    typingWrapper.remove();

    const replyText = res.ok ? data.reply : '⚠️ Sorry, I couldn\'t process that request. Please try again!';
    appendBubble('bot', replyText, true);
  } catch {
    typingWrapper.remove();
    appendBubble('bot', '⚠️ Cannot connect to the server. Please make sure the backend is running and try again.');
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send ➤';
    input.disabled = false;
    input.focus();
  }
}

function askSuggestion(btn) {
  const input = document.getElementById('chat-input');
  input.value = btn.textContent;
  sendMessage();
}


// ═══════════════════════════════════════════════════════════
//  Monthly Income
// ═══════════════════════════════════════════════════════════
function promptSetMonthlyIncome() {
  const amount = prompt('Enter your fixed monthly income (₹):');
  if (amount === null) return;
  const num = parseFloat(amount);
  if (isNaN(num) || num < 0) {
    showToast('Please enter a valid amount.', 'error');
    return;
  }
  setMonthlyIncome(num);
}

async function setMonthlyIncome(amount) {
  try {
    const res = await authFetch(`${API}/api/profile/income`, {
      method: 'PUT',
      headers: { ...authHeader(), 'Content-Type': 'application/json' },
      body: JSON.stringify({ monthly_income: amount }),
    });
    if (res.ok) {
      showToast('Monthly income updated!', 'success');
      const link = document.querySelector('.set-income-link');
      if (link) link.remove();
      loadDashboardSummary();
    } else {
      showToast('Failed to update income.', 'error');
    }
  } catch {
    showToast('Cannot connect to server.', 'error');
  }
}


// ═══════════════════════════════════════════════════════════
//  Init
// ═══════════════════════════════════════════════════════════
document.addEventListener('DOMContentLoaded', async () => {
  document.body.style.opacity = '1';
  const ok = await guardAuth();
  if (!ok) return;

  const yearInput = document.getElementById('budget-year');
  if (yearInput) yearInput.value = new Date().getFullYear();

  initNav();
  initExpenseChart();
  initCategoryChart();

  // Run both independently so ML insights always load
  await loadDashboardSummary();
  loadMLInsights();
});


// ═══════════════════════════════════════════════════════════
//  Support Section
// ═══════════════════════════════════════════════════════════
function toggleFaq(id) {
  const item = document.getElementById(id);
  if (!item) return;
  const isOpen = item.classList.contains('faq-open');
  document.querySelectorAll('.faq-item.faq-open').forEach(el => el.classList.remove('faq-open'));
  if (!isOpen) item.classList.add('faq-open');
}


// ═══════════════════════════════════════════════════════════
//  BANK ACCOUNTS — Live Banking Adapter
// ═══════════════════════════════════════════════════════════

let _selectedAccountId = null;
let _bankInitialized   = false;   // only auto-load once per session

// ── Shared fetch helper for bank endpoints ─────────────────
async function bankFetch(path, options = {}) {
  const url = `${API}${path}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };
  const res = await authFetch(url, { ...options, headers });
  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    try {
      const d = await res.json();
      msg = d.detail || d.message || d.error || msg;
    } catch { /* non-JSON body */ }
    throw new Error(msg);
  }
  // 204 No Content
  if (res.status === 204) return {};
  return res.json();
}

// ── Section entry point ────────────────────────────────────
async function initBankSection() {
  if (_bankInitialized) return;   // don't reload on every tab click
  _bankInitialized = true;
  try {
    const status = await bankFetch('/api/bank/status');
    if (status.linked) {
      showBankConnectedState(status);
      await loadBankAccounts();
    } else {
      showBankDisconnectedState();
    }
  } catch (err) {
    console.error('Bank init error:', err);
    showBankDisconnectedState();
    showToast('️ Could not check bank status.', 'warning');
  }
}

function showBankDisconnectedState() {
  document.getElementById('bank-connect-panel').style.display  = 'block';
  document.getElementById('bank-accounts-panel').style.display = 'none';
  document.getElementById('bank-sync-btn').style.display       = 'none';
  document.getElementById('bank-disconnect-btn').style.display = 'none';
  document.getElementById('bank-status-text').textContent =
    'Connect your bank to view real-time balances and transactions';
}

function showBankConnectedState(status) {
  document.getElementById('bank-connect-panel').style.display  = 'none';
  document.getElementById('bank-accounts-panel').style.display = 'block';
  document.getElementById('bank-sync-btn').style.display       = 'inline-flex';
  document.getElementById('bank-disconnect-btn').style.display = 'inline-flex';
  const label = status.bank_label || 'Bank';
  const since = status.linked_at
    ? new Date(status.linked_at).toLocaleDateString('en-IN',
        { day: '2-digit', month: 'short', year: 'numeric' })
    : '';
  document.getElementById('bank-status-text').textContent =
    `Connected to ${label}${since ? ' · since ' + since : ''}`;
}

function selectAdapter(type) {
  document.querySelectorAll('.adapter-tab').forEach(btn =>
    btn.classList.toggle('active', btn.dataset.adapter === type));
  document.querySelectorAll('.adapter-form').forEach(f =>
    f.classList.toggle('hidden', !f.id.endsWith(type)));
}

// ── Connect bank ───────────────────────────────────────────
async function connectBank(adapter) {
  const btnId   = adapter === 'mock' ? 'mock-connect-btn' : 'obp-connect-btn';
  const btn     = document.getElementById(btnId);
  if (!btn) return;
  const text    = btn.querySelector('.btn-text');
  const spinner = btn.querySelector('.btn-spinner');
  btn.disabled  = true;
  if (spinner) spinner.classList.remove('hidden');
  if (text)    text.textContent = 'Connecting…';

  const body = { adapter };
  if (adapter === 'obp') {
    body.username     = (document.getElementById('obp-username') || {}).value?.trim() || '';
    body.password     = (document.getElementById('obp-password') || {}).value || '';
    body.consumer_key = (document.getElementById('obp-consumer-key') || {}).value?.trim() || '';
    if (!body.username || !body.password || !body.consumer_key) {
      showToast('️ Please enter your OBP username, password, and Consumer Key.', 'warning');
      btn.disabled = false;
      if (spinner) spinner.classList.add('hidden');
      if (text)    text.textContent = 'Connect OBP Sandbox';
      return;
    }
  }

  try {
    const res = await bankFetch('/api/bank/connect', {
      method: 'POST',
      body:   JSON.stringify(body),
    });
    showToast(res.message || ' Bank connected!', 'success');
    _bankInitialized = false;   // reset so loadBankAccounts re-runs
    showBankConnectedState({ bank_label: res.bank_label });
    await loadBankAccounts();
  } catch (err) {
    console.error('Bank connect error:', err);
    showToast(` ${err.message}`, 'error', 7000);
  } finally {
    btn.disabled = false;
    if (spinner) spinner.classList.add('hidden');
    if (text)    text.textContent =
      adapter === 'mock' ? 'Connect Demo Bank' : 'Connect OBP Sandbox';
  }
}

// ── Load accounts ──────────────────────────────────────────
async function loadBankAccounts() {
  const grid = document.getElementById('bank-accounts-grid');
  grid.innerHTML = '<p class="bank-loading-msg">⏳ Loading accounts…</p>';
  try {
    const accounts = await bankFetch('/api/bank/accounts');
    if (!accounts || !accounts.length) {
      grid.innerHTML = '<p class="bank-loading-msg">No accounts found.</p>';
      return;
    }
    grid.innerHTML = '';
    accounts.forEach((acct, idx) => {
      const card = document.createElement('div');
      card.className = 'bank-account-card' + (idx === 0 ? ' selected' : '');
      card.setAttribute('role', 'button');
      card.setAttribute('tabindex', '0');
      card.dataset.accountId = acct.account_id;
      card.innerHTML = `
        <div class="bank-card-top">
          <div class="bank-card-logo">${_bankLogo(acct.bank_name)}</div>
          <div class="bank-card-type">${acct.account_type}</div>
        </div>
        <div class="bank-card-name">${acct.bank_name}</div>
        <div class="bank-card-number">${acct.masked_number}</div>
        <div class="bank-card-balance">
          <span class="bank-balance-label">Available Balance</span>
          <span class="bank-balance-amount">₹${acct.balance.toLocaleString('en-IN', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}</span>
        </div>`;
      card.onclick    = () => selectBankAccount(acct.account_id, acct.bank_name);
      card.onkeydown  = e => { if (e.key === 'Enter' || e.key === ' ') card.click(); };
      grid.appendChild(card);
    });

    // Auto-select first
    if (accounts.length > 0) selectBankAccount(accounts[0].account_id, accounts[0].bank_name);

  } catch (err) {
    console.error('Load accounts error:', err);
    grid.innerHTML = `<p class="bank-loading-msg" style="color:#ef4444;"> ${err.message}</p>`;
  }
}

function selectBankAccount(accountId, bankName) {
  _selectedAccountId = accountId;
  document.querySelectorAll('.bank-account-card').forEach(c =>
    c.classList.toggle('selected', c.dataset.accountId === accountId));
  const panel = document.getElementById('bank-txn-panel');
  if (panel) panel.style.display = 'block';
  const title = document.getElementById('bank-txn-title');
  if (title) title.textContent = `${bankName} — Transactions`;
  loadBankTransactions();
}

// ── Load transactions ─────────────────────────────────────
async function loadBankTransactions() {
  if (!_selectedAccountId) return;
  const days    = (document.getElementById('bank-txn-days') || {}).value || 90;
  const loading = document.getElementById('bank-txn-loading');
  const tbody   = document.getElementById('bank-txn-tbody');
  const empty   = document.getElementById('bank-txn-empty');
  const table   = document.getElementById('bank-txn-table');
  const banner  = document.getElementById('bank-import-result');

  if (loading) loading.classList.remove('hidden');
  if (table)   table.style.display = 'none';
  if (empty)   empty.classList.add('hidden');
  if (banner)  banner.classList.add('hidden');
  if (tbody)   tbody.innerHTML = '';

  try {
    const txns = await bankFetch(
      `/api/bank/transactions?account_id=${encodeURIComponent(_selectedAccountId)}&days=${days}`
    );
    if (loading) loading.classList.add('hidden');

    if (!txns || !txns.length) {
      if (empty) {
        empty.textContent = 'No transactions found for this period.';
        empty.classList.remove('hidden');
      }
      return;
    }

    if (table) table.style.display = 'table';

    const CAT_COLOR = {
      Food:'#f59e0b', Transport:'#3b82f6', Utilities:'#8b5cf6',
      Entertainment:'#ec4899', Shopping:'#10b981', Healthcare:'#ef4444',
      Education:'#06b6d4', Rent:'#f97316', Income:'#22c55e', Other:'#6b7280',
    };

    txns.forEach(t => {
      const tr    = document.createElement('tr');
      const color = CAT_COLOR[t.category] || '#6b7280';
      const isInc = t.type === 'Income';
      const d     = new Date(t.date);
      const dateStr = isNaN(d) ? t.date.slice(0,10)
        : d.toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' });

      tr.innerHTML = `
        <td>${dateStr}</td>
        <td class="bank-txn-desc" title="${_esc(t.description)}">${_esc(t.description)}</td>
        <td><span class="cat-badge" style="background:${color}22;color:${color}">${t.category}</span></td>
        <td><span class="type-badge ${isInc ? 'income' : 'expense'}">${t.type}</span></td>
        <td style="text-align:right;font-weight:600;color:${isInc ? '#22c55e' : '#ef4444'}">
          ${isInc ? '+' : '-'}₹${t.amount.toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2})}
        </td>
        <td style="text-align:right;color:var(--text-muted)">
          ₹${t.balance_after.toLocaleString('en-IN',{minimumFractionDigits:2,maximumFractionDigits:2})}
        </td>`;
      tbody.appendChild(tr);
    });

    const sub = document.getElementById('bank-txn-subtitle');
    if (sub) sub.textContent = `${txns.length} transactions · last ${days} days`;

  } catch (err) {
    console.error('Load transactions error:', err);
    if (loading) loading.classList.add('hidden');
    if (empty) {
      empty.textContent = ` ${err.message}`;
      empty.classList.remove('hidden');
    }
  }
}

// ── Import transactions ────────────────────────────────────
async function importBankTransactions() {
  if (!_selectedAccountId) return;
  const days   = (document.getElementById('bank-txn-days') || {}).value || 90;
  const btn    = document.getElementById('bank-import-btn');
  const banner = document.getElementById('bank-import-result');
  if (btn) { btn.disabled = true; btn.textContent = 'Importing…'; }
  if (banner) banner.classList.add('hidden');

  try {
    const res = await bankFetch('/api/bank/import-live', {
      method: 'POST',
      body:   JSON.stringify({ account_id: _selectedAccountId, days: parseInt(days) }),
    });
    const msg = res.imported > 0
      ? ` ${res.imported} transactions imported!${res.skipped_duplicate ? ` (${res.skipped_duplicate} already existed)` : ''}`
      : `ℹ️ All ${res.skipped_duplicate} transactions already exist.`;
    if (banner) {
      banner.textContent = msg;
      banner.className = `import-result-banner ${res.imported > 0 ? 'success' : 'info'}`;
      banner.classList.remove('hidden');
    }
    if (res.imported > 0 || res.skipped_duplicate > 0) {
      loadDashboardSummary();
      const tbody = document.getElementById('bank-txn-tbody');
      const table = document.getElementById('bank-txn-table');
      const empty = document.getElementById('bank-txn-empty');
      if (tbody) tbody.innerHTML = '';
      if (table) table.style.display = 'none';
      if (empty) {
        empty.textContent = '🎉 All transactions imported and synced to FinAly AI!';
        empty.style.color = '#10b981';
        empty.classList.remove('hidden');
      }
      if (btn) btn.style.display = 'none';
    }
  } catch (err) {
    if (banner) {
      banner.textContent = ` Import failed: ${err.message}`;
      banner.className = 'import-result-banner error';
      banner.classList.remove('hidden');
    }
  } finally {
    if (btn && btn.style.display !== 'none') { btn.disabled = false; btn.innerHTML = ' Import to FinAly'; }
  }
}

// ── Sync & disconnect ──────────────────────────────────────
async function syncBankAccounts() {
  await loadBankAccounts();
  showToast(' Bank data refreshed!', 'success');
}

async function disconnectBank() {
  if (!confirm('Disconnect your bank? You can reconnect at any time.')) return;
  try {
    await bankFetch('/api/bank/disconnect', { method: 'DELETE' });
    showToast('Bank disconnected.', 'info');
    _bankInitialized   = false;
    _selectedAccountId = null;
    showBankDisconnectedState();
    const grid  = document.getElementById('bank-accounts-grid');
    const panel = document.getElementById('bank-txn-panel');
    if (grid)  grid.innerHTML    = '';
    if (panel) panel.style.display = 'none';
  } catch (err) {
    showToast(` ${err.message}`, 'error');
  }
}

// ── Helpers ───────────────────────────────────────────────
function _bankLogo(name) {
  const m = {
    'HDFC Bank':'', 'State Bank of India':'️',
    'ICICI Bank':'', 'Axis Bank':'',
    'Kotak Mahindra Bank':'', 'Yes Bank':'', 'OBP Bank':'',
  };
  return m[name] || '';
}

function _esc(s) {
  return String(s)
    .replace(/&/g,'&amp;').replace(/</g,'&lt;')
    .replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}


// ═══════════════════════════════════════════════════════════
//  Export Section — Data & Filter Engine
// ═══════════════════════════════════════════════════════════

let _allExportTxns = [];
let _filteredExportTxns = [];
let _exportPage = 1;
const EXPORT_PAGE_SIZE = 25;

async function initExportSection() {
  const tbody = document.getElementById('export-tbody');
  if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="export-loading">Loading transactions…</td></tr>';
  try {
    const res = await authFetch(`${API}/api/transactions`);
    if (!res.ok) throw new Error('Failed to load');
    _allExportTxns = await res.json();
    applyExportFilters();
  } catch (err) {
    if (tbody) tbody.innerHTML = '<tr><td colspan="6" class="export-loading" style="color:#ef4444">Failed to load transactions. Please try again.</td></tr>';
  }
}

function applyExportFilters() {
  const fromVal = document.getElementById('export-date-from')?.value || '';
  const toVal   = document.getElementById('export-date-to')?.value   || '';
  const cat     = document.getElementById('export-category')?.value  || 'All';
  const type    = document.getElementById('export-type')?.value      || 'All';
  const from = fromVal ? new Date(fromVal) : null;
  const to   = toVal   ? new Date(toVal + 'T23:59:59') : null;
  _filteredExportTxns = _allExportTxns.filter(t => {
    const d = new Date(t.date);
    if (from && d < from) return false;
    if (to   && d > to)   return false;
    if (cat  !== 'All' && t.category !== cat)           return false;
    if (type !== 'All' && t.transaction_type !== type)  return false;
    return true;
  });
  _exportPage = 1;
  renderExportStats();
  renderExportTable();
}

function renderExportStats() {
  const countEl   = document.getElementById('export-count');
  const incomeEl  = document.getElementById('export-total-income');
  const expenseEl = document.getElementById('export-total-expense');
  const netEl     = document.getElementById('export-net-balance');
  const titleEl   = document.getElementById('export-table-title');
  let totalIncome = 0, totalExpense = 0;
  _filteredExportTxns.forEach(t => {
    if (t.transaction_type === 'Income')  totalIncome  += t.amount;
    if (t.transaction_type === 'Expense') totalExpense += t.amount;
  });
  const net = totalIncome - totalExpense;
  if (countEl)   countEl.textContent   = _filteredExportTxns.length.toLocaleString('en-IN');
  if (incomeEl)  incomeEl.textContent  = formatCurrency(totalIncome);
  if (expenseEl) expenseEl.textContent = formatCurrency(totalExpense);
  if (netEl) {
    netEl.textContent = (net >= 0 ? '+' : '-') + formatCurrency(Math.abs(net));
    netEl.style.color = net >= 0 ? 'var(--green)' : 'var(--red)';
  }
  if (titleEl) titleEl.textContent = `Transaction Preview (${_filteredExportTxns.length.toLocaleString('en-IN')} records)`;
}

function renderExportTable() {
  const tbody = document.getElementById('export-tbody');
  const pagEl = document.getElementById('export-pagination');
  if (!tbody) return;
  if (!_filteredExportTxns.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="export-loading">No transactions match the selected filters.</td></tr>';
    if (pagEl) pagEl.innerHTML = '';
    return;
  }
  const totalPages = Math.ceil(_filteredExportTxns.length / EXPORT_PAGE_SIZE);
  const start = (_exportPage - 1) * EXPORT_PAGE_SIZE;
  const page  = _filteredExportTxns.slice(start, start + EXPORT_PAGE_SIZE);
  const SOURCE_LABEL = { manual: 'Manual', bank_csv: 'CSV Import', bank_pdf: 'PDF Import', bank_aa: 'Live Bank' };
  const rows = page.map(t => {
    const isInc  = t.transaction_type === 'Income';
    const amt    = (isInc ? '+' : '-') + formatCurrency(t.amount);
    const d      = new Date(t.date);
    const dateStr = isNaN(d.getTime()) ? (t.date || '').slice(0,10) : d.toLocaleDateString('en-IN', { day:'2-digit', month:'short', year:'numeric' });
    const rawDesc = t.description || t.category || '';
    const desc   = _esc(rawDesc.length > 48 ? rawDesc.slice(0,48) + '…' : rawDesc);
    const src    = SOURCE_LABEL[t.import_source] || 'Manual';
    return `<tr class="export-row ${isInc ? 'export-row--income' : 'export-row--expense'}">
      <td class="export-cell-date">${dateStr}</td>
      <td class="export-cell-desc" title="${_esc(rawDesc)}">${desc}</td>
      <td><span class="export-cat-badge">${_esc(t.category)}</span></td>
      <td><span class="export-type-badge ${isInc ? 'type-income' : 'type-expense'}">${_esc(t.transaction_type)}</span></td>
      <td class="export-cell-amount ${isInc ? 'amt-income' : 'amt-expense'}">${amt}</td>
      <td class="export-cell-source">${src}</td>
    </tr>`;
  });
  tbody.innerHTML = rows.join('');
  // Pagination
  if (pagEl) {
    if (totalPages > 1) {
      const startP = Math.max(1, _exportPage - 2);
      const endP   = Math.min(totalPages, startP + 4);
      let html = `<span class="export-page-info">Page ${_exportPage} of ${totalPages} &nbsp;&middot;&nbsp; ${_filteredExportTxns.length} records</span><div class="export-page-btns">`;
      if (_exportPage > 1)          html += `<button class="export-page-btn" onclick="goExportPage(${_exportPage - 1})">&#8249; Prev</button>`;
      for (let p = startP; p <= endP; p++)
        html += `<button class="export-page-btn ${p === _exportPage ? 'active' : ''}" onclick="goExportPage(${p})">${p}</button>`;
      if (_exportPage < totalPages) html += `<button class="export-page-btn" onclick="goExportPage(${_exportPage + 1})">Next &#8250;</button>`;
      html += '</div>';
      pagEl.innerHTML = html;
    } else {
      pagEl.innerHTML = '';
    }
  }
}

function goExportPage(page) {
  _exportPage = page;
  renderExportTable();
  document.getElementById('export-table')?.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function setExportPreset(preset) {
  ['all', 'month', '30', '90'].forEach(p => {
    const btn = document.getElementById(`pill-${p}`);
    if (btn) btn.classList.toggle('active', p === preset);
  });
  const fromEl = document.getElementById('export-date-from');
  const toEl   = document.getElementById('export-date-to');
  if (!fromEl || !toEl) return;
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  const fmt = d => `${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;
  if (preset === 'all') {
    fromEl.value = '';
    toEl.value   = '';
  } else if (preset === 'month') {
    fromEl.value = fmt(new Date(now.getFullYear(), now.getMonth(), 1));
    toEl.value   = fmt(now);
  } else if (preset === '30') {
    const d = new Date(); d.setDate(d.getDate() - 30);
    fromEl.value = fmt(d); toEl.value = fmt(now);
  } else if (preset === '90') {
    const d = new Date(); d.setDate(d.getDate() - 90);
    fromEl.value = fmt(d); toEl.value = fmt(now);
  }
  applyExportFilters();
}

function resetExportFilters() {
  const fromEl = document.getElementById('export-date-from');
  const toEl   = document.getElementById('export-date-to');
  const catEl  = document.getElementById('export-category');
  const typeEl = document.getElementById('export-type');
  if (fromEl) fromEl.value = '';
  if (toEl)   toEl.value   = '';
  if (catEl)  catEl.value  = 'All';
  if (typeEl) typeEl.value = 'All';
  setExportPreset('all');
  showToast('Filters reset — showing all records', 'info');
}

async function downloadExport(format) {
  if (!_filteredExportTxns.length) {
    showToast('No records to export with the current filters.', 'warning');
    return;
  }
  const fromEl = document.getElementById('export-date-from')?.value || '';
  const toEl   = document.getElementById('export-date-to')?.value   || '';
  const catEl  = document.getElementById('export-category')?.value  || 'All';
  const typeEl = document.getElementById('export-type')?.value      || 'All';
  const params = new URLSearchParams();
  if (fromEl) params.append('date_from', fromEl);
  if (toEl)   params.append('date_to',   toEl);
  if (catEl  && catEl  !== 'All') params.append('category', catEl);
  if (typeEl && typeEl !== 'All') params.append('txn_type', typeEl);
  const btnId = format === 'excel' ? 'export-excel-btn' : 'export-pdf-btn';
  const btn   = document.getElementById(btnId);
  if (btn) { btn.disabled = true; btn.classList.add('export-btn--loading'); }
  showToast(`⏳ Generating ${format === 'excel' ? 'Excel Spreadsheet' : 'PDF Report'} for ${_filteredExportTxns.length} records…`, 'info', 8000);
  try {
    const res = await authFetch(`${API}/api/export/${format}?${params.toString()}`);
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      showToast(data.detail || `Export failed (${res.status})`, 'error');
      return;
    }
    const blob = await res.blob();
    const url  = window.URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    const disp = res.headers.get('Content-Disposition') || '';
    let filename = `FinAly_${format === 'excel' ? 'Transactions.xlsx' : 'Report.pdf'}`;
    if (disp.includes('filename=')) {
      filename = disp.split('filename=')[1].replace(/["';]/g, '').trim();
    }
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.URL.revokeObjectURL(url);
    showToast(`✅ ${format === 'excel' ? 'Excel Spreadsheet' : 'PDF Report'} downloaded successfully!`, 'success');
  } catch {
    showToast('Network error during export. Please ensure the server is running.', 'error');
  } finally {
    if (btn) { btn.disabled = false; btn.classList.remove('export-btn--loading'); }
  }
}
