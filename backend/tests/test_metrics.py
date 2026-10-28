from datetime import datetime

from app.evaluation.metrics import order_correct, pairwise_grouping, prf, set_prf


def test_prf():
    assert prf(8, 2, 2) == {"precision": 0.8, "recall": 0.8, "f1": 0.8, "tp": 8, "fp": 2, "fn": 2}
    assert prf(0, 0, 5)["precision"] is None


def test_pairwise_grouping_exact():
    truth = {"a": "g1", "b": "g1", "c": "g1", "d": "g2", "e": None}
    perfect = pairwise_grouping({"a": 1, "b": 1, "c": 1, "d": 2}, truth, set(truth))
    assert perfect["f1"] == 1.0
    merged = pairwise_grouping({"a": 1, "b": 1, "c": 1, "d": 1}, truth, set(truth))
    assert merged["tp"] == 3 and merged["fp"] == 3 and merged["recall"] == 1.0 and merged["precision"] == 0.5
    split = pairwise_grouping({"a": 1, "b": 1, "c": 2, "d": 3}, truth, set(truth))
    assert split["tp"] == 1 and split["fn"] == 2


def test_set_prf_and_order():
    assert set_prf({"a", "b"}, {"b", "c"}) == (1, 1, 1)
    t = datetime(2026, 1, 1)
    assert order_correct({"x": t, "y": t.replace(hour=1)}, ["x", "y"]) is True
    assert order_correct({"x": t.replace(hour=2), "y": t}, ["x", "y"]) is False
    assert order_correct({"x": t}, ["x", "y"]) is None
