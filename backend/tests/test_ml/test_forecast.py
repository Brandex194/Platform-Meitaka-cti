import pytest

from app.ml.forecast import forecast_scores


def test_returns_horizon_values():
    data = [0.3 + i * 0.01 for i in range(30)]
    result = forecast_scores(data, horizon=7)
    assert len(result) == 7


def test_upward_trend_continues():
    data = [0.1 * i / 29 for i in range(30)]
    result = forecast_scores(data, horizon=7)
    assert result[-1] > result[0]


def test_all_values_clamped_0_to_1():
    data = [0.99] * 30
    result = forecast_scores(data, horizon=7)
    assert all(0.0 <= v <= 1.0 for v in result)


def test_raises_on_too_few_points():
    with pytest.raises(ValueError, match="at least 2"):
        forecast_scores([0.5], horizon=3)
