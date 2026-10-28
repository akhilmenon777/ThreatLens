"""Metric helpers (pure functions, unit-tested)."""
from __future__ import annotations

from collections import Counter


def prf(tp: float, fp: float, fn: float) -> dict:
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    return {"precision": _r(p), "recall": _r(r), "f1": _r(f), "tp": tp, "fp": fp, "fn": fn}


def _r(x):
    return None if x is None else round(x, 4)


def _pairs(n: int) -> int:
    return n * (n - 1) // 2


def pairwise_grouping(pred: dict[str, str | None], truth: dict[str, str | None], universe: set[str]) -> dict:
    """Pair-counting precision/recall/F1 for event grouping.

    pred/truth map event_id -> cluster id (None = not grouped / singleton).
    Unit: unordered pairs of events in ``universe``. A pair is predicted-positive
    when both events are in the same predicted incident; truth-positive when both
    belong to the same labelled group. Computed via contingency counts, so it is
    exact and O(n) even for groups with thousands of events.
    """
    cont: Counter = Counter()
    pc: Counter = Counter()
    tc: Counter = Counter()
    for e in universe:
        p, t = pred.get(e), truth.get(e)
        if p is not None:
            pc[p] += 1
        if t is not None:
            tc[t] += 1
        if p is not None and t is not None:
            cont[(p, t)] += 1
    tp = sum(_pairs(n) for n in cont.values())
    pred_pos = sum(_pairs(n) for n in pc.values())
    true_pos = sum(_pairs(n) for n in tc.values())
    return prf(tp, pred_pos - tp, true_pos - tp)


def set_prf(predicted: set, expected: set) -> tuple[int, int, int]:
    return len(predicted & expected), len(predicted - expected), len(expected - predicted)


def order_correct(stage_first_ts: dict[str, object], expected_order: list[str]) -> bool | None:
    seq = [s for s in expected_order if stage_first_ts.get(s) is not None]
    if len(seq) < 2:
        return None
    times = [stage_first_ts[s] for s in seq]
    return all(a <= b for a, b in zip(times, times[1:]))


SEVERITY_RANK = {"Informational": 0, "Low": 1, "Medium": 2, "High": 3, "Critical": 4}
