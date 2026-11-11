import numpy as np


def forecast_scores(daily_avgs: list[float], horizon: int = 7) -> list[float]:
    """OLS linear forecast over daily_avgs for `horizon` future steps, clamped to [0.0, 1.0]."""
    if len(daily_avgs) < 2:
        raise ValueError("forecast_scores requires at least 2 data points")
    x = np.arange(len(daily_avgs), dtype=float)
    coeffs = np.polyfit(x, daily_avgs, deg=1)
    future_x = np.arange(len(daily_avgs), len(daily_avgs) + horizon, dtype=float)
    forecast = np.polyval(coeffs, future_x)
    return np.clip(forecast, 0.0, 1.0).tolist()
