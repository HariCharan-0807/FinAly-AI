"""
FinAly AI — Smart Spending Intelligence Engine.
Uses a blended forecasting approach:
  - Short-term baseline: average of last 30 days actual spending
  - Trend adjustment: OLS linear regression slope on the last 90 days
  - Anomaly detection: Z-score analysis on transaction amounts
"""
from datetime import datetime, timedelta, timezone, date as _date
from sqlalchemy.orm import Session
from models import Transaction
import math


def run_classical_ml_analytics(db: Session, user_id: int) -> dict:
    """
    Run smart spending analytics on historical transaction data.
    Returns an estimated next month's expenditure and spending anomalies.
    """
    now = datetime.now(timezone.utc)

    # ── Fetch last 90 days of expenses ─────────────────────────────────
    ninety_days_ago = now - timedelta(days=90)
    txns = db.query(Transaction).filter(
        Transaction.user_id == user_id,
        Transaction.transaction_type == "Expense",
        Transaction.date >= ninety_days_ago
    ).order_by(Transaction.date.asc()).all()

    if not txns:
        return {
            "model_status": "insufficient_data",
            "message": "Add at least 1 expense transaction to see your spending forecast.",
            "forecast": None,
            "anomalies": []
        }

    # ── Aggregate daily totals across the full 90-day window ───────────
    daily_spend = {}
    for t in txns:
        day_key = t.date.date() if hasattr(t.date, 'date') else t.date
        if isinstance(day_key, str):
            try:
                day_key = _date.fromisoformat(day_key[:10])
            except Exception:
                continue
        daily_spend[day_key] = daily_spend.get(day_key, 0.0) + t.amount

    # Fill in zero-spend days so the regression slope is correct
    all_days = sorted(daily_spend.keys())
    if all_days:
        start_day = all_days[0]
        end_day   = all_days[-1]
        current   = start_day
        while current <= end_day:
            if current not in daily_spend:
                daily_spend[current] = 0.0
            current += timedelta(days=1)

    sorted_days = sorted(daily_spend.keys())
    n = len(sorted_days)
    y_vals = [daily_spend[d] for d in sorted_days]

    # ── Baseline: average daily spend over last 30 days ────────────────
    thirty_days_ago = now - timedelta(days=30)
    last_30_amounts = [
        t.amount for t in txns
        if t.date is not None and (
            t.date if isinstance(t.date, datetime) else
            datetime.combine(t.date, datetime.min.time(), tzinfo=timezone.utc)
        ) >= thirty_days_ago
    ]
    last_30_total = sum(last_30_amounts) if last_30_amounts else sum(y_vals)
    # Normalize to exactly 30 days (not just transaction days)
    baseline_monthly = round(last_30_total, 2)

    # ── OLS Linear Regression for trend adjustment ──────────────────────
    if n >= 2:
        x_vals = list(range(n))
        sum_x  = sum(x_vals)
        sum_y  = sum(y_vals)
        sum_xy = sum(x * y for x, y in zip(x_vals, y_vals))
        sum_xx = sum(x * x for x in x_vals)

        denom  = (n * sum_xx - sum_x * sum_x)
        slope  = (n * sum_xy - sum_x * sum_y) / denom if denom != 0 else 0.0
        intercept = (sum_y - slope * sum_x) / n

        # Trend over next 30 days vs last 30 days
        last_30_idx_start = max(0, n - 30)
        last_30_pred  = slope * (last_30_idx_start + n) / 2 + intercept
        next_30_pred  = slope * (n + n + 30) / 2 + intercept
        trend_delta   = (next_30_pred - last_30_pred) * 30  # ₹ change

        # Blended forecast: baseline + half the trend signal (dampened)
        predicted_next_30d = max(round(baseline_monthly + trend_delta * 0.5, 2), 0.0)

        # R² score
        mean_y  = sum_y / n
        ss_tot  = sum((y - mean_y) ** 2 for y in y_vals)
        ss_res  = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(x_vals, y_vals))
        r2_score = round(1 - (ss_res / ss_tot), 3) if ss_tot != 0 else 1.0

        trend = "increasing" if slope > 2 else ("decreasing" if slope < -2 else "stable")
    else:
        # Only 1 unique day of data — use that day as daily average × 30
        day_avg = y_vals[0] if y_vals else 0.0
        predicted_next_30d = round(day_avg * 30, 2)
        slope  = 0.0
        r2_score = 1.0
        trend  = "stable"

    # ── Z-Score Anomaly Detection ───────────────────────────────────────
    amounts  = [t.amount for t in txns]
    mean_amt = sum(amounts) / len(amounts)
    variance = sum((a - mean_amt) ** 2 for a in amounts) / len(amounts)
    std_dev  = math.sqrt(variance)

    anomalies = []
    if std_dev > 0:
        for t in txns:
            z_score = (t.amount - mean_amt) / std_dev
            if z_score >= 1.96:
                anomalies.append({
                    "id": t.id,
                    "description": t.description or t.category,
                    "amount": round(t.amount, 2),
                    "category": t.category,
                    "date": t.date.strftime("%Y-%m-%d") if hasattr(t.date, 'strftime') else str(t.date)[:10],
                    "z_score": round(z_score, 2),
                    "confidence_pct": min(round((1 - math.exp(-z_score)) * 100, 1), 99.9)
                })

    anomalies.sort(key=lambda a: a["z_score"], reverse=True)

    return {
        "model_status": "active",
        "forecast": {
            "predicted_next_30d_expenses": predicted_next_30d,
            "last_30d_actual": round(baseline_monthly, 2),
            "expenditure_trend": trend,
        },
        "anomalies": anomalies[:5]
    }

