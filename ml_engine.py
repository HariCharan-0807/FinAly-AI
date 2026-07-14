"""
FinAly AI — Classical Machine Learning Analytics Engine.
Implements Ordinary Least Squares (OLS) Linear Regression for time-series expenditure forecasting,
and Z-Score Statistical Distribution Analysis for spending anomaly & fraud detection.
"""
from datetime import datetime, timedelta, timezone
from sqlalchemy.orm import Session
from models import Transaction
import math

def run_classical_ml_analytics(db: Session, user_id: int) -> dict:
    """
    Run classical statistical machine learning models on historical transaction data.
    """
    # Fetch last 90 days of expense transactions
    ninety_days_ago = datetime.now(timezone.utc) - timedelta(days=90)
    txns = db.query(Transaction).filter(
        Transaction.user_id == user_id,
        Transaction.transaction_type == "Expense",
        Transaction.date >= ninety_days_ago
    ).order_by(Transaction.date.asc()).all()

    if not txns:
        return {
            "model_status": "insufficient_data",
            "message": "At least 1 expense transaction required for ML model inference.",
            "forecast": None,
            "anomalies": []
        }

    # ── 1. OLS Linear Regression Forecasting ───────────────────────────
    # Aggregate daily spending
    daily_spend = {}
    for t in txns:
        day_str = t.date.strftime("%Y-%m-%d") if t.date else datetime.now().strftime("%Y-%m-%d")
        daily_spend[day_str] = daily_spend.get(day_str, 0.0) + t.amount

    sorted_days = sorted(daily_spend.keys())
    n = len(sorted_days)

    if n >= 2:
        x_vals = list(range(n))
        y_vals = [daily_spend[d] for d in sorted_days]

        sum_x = sum(x_vals)
        sum_y = sum(y_vals)
        sum_xy = sum(x * y for x, y in zip(x_vals, y_vals))
        sum_xx = sum(x * x for x in x_vals)

        denominator = (n * sum_xx - sum_x * sum_x)
        slope = (n * sum_xy - sum_x * sum_y) / denominator if denominator != 0 else 0.0
        intercept = (sum_y - slope * sum_x) / n

        # Predict next 30 days total spending
        future_day_start = n
        future_day_end = n + 30
        predicted_daily_avg = slope * (future_day_start + future_day_end) / 2 + intercept
        predicted_next_30d = max(round(predicted_daily_avg * 30, 2), 0.0)

        # Calculate R^2 coefficient of determination
        mean_y = sum_y / n
        ss_tot = sum((y - mean_y) ** 2 for y in y_vals)
        ss_res = sum((y - (slope * x + intercept)) ** 2 for x, y in zip(x_vals, y_vals))
        r2_score = round(1 - (ss_res / ss_tot), 3) if ss_tot != 0 else 1.0

        trend = "increasing" if slope > 5 else ("decreasing" if slope < -5 else "stable")
    else:
        # Single day fallback
        total_spent = sum(t.amount for t in txns)
        predicted_next_30d = round(total_spent * 30, 2)
        slope = 0.0
        r2_score = 1.0
        trend = "stable"

    # ── 2. Z-Score Statistical Anomaly Detection ───────────────────────
    amounts = [t.amount for t in txns]
    mean_amt = sum(amounts) / len(amounts)
    variance = sum((a - mean_amt) ** 2 for a in amounts) / len(amounts)
    std_dev = math.sqrt(variance)

    anomalies = []
    if std_dev > 0:
        for t in txns:
            z_score = (t.amount - mean_amt) / std_dev
            if z_score >= 1.96: # 95% statistical confidence threshold
                anomalies.append({
                    "id": t.id,
                    "description": t.description or t.category,
                    "amount": round(t.amount, 2),
                    "category": t.category,
                    "date": t.date.strftime("%Y-%m-%d") if t.date else "",
                    "z_score": round(z_score, 2),
                    "confidence_pct": min(round((1 - math.exp(-z_score)) * 100, 1), 99.9)
                })

    anomalies.sort(key=lambda a: a["z_score"], reverse=True)

    return {
        "model_status": "active",
        "algorithms": {
            "time_series_forecasting": "Ordinary Least Squares (OLS) Linear Regression",
            "anomaly_detection": "Gaussian Z-Score Distribution Analysis"
        },
        "forecast": {
            "predicted_next_30d_expenses": predicted_next_30d,
            "expenditure_trend": trend,
            "regression_slope": round(slope, 2),
            "r2_accuracy_score": r2_score
        },
        "anomalies": anomalies[:5] # Return top 5 most severe spending anomalies
    }
