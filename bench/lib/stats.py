#!/usr/bin/env python3
"""Shared statistics helpers for the bench suite (stdlib only).

Conventions follow the methodology doc (bench/README.md):
- every point metric is reported as mean +/- sigma with min..max
- latency distributions report p50/p90/p95/p99 plus a fixed log2-bucket
  histogram so the distribution shape is inspectable without re-reading
  the raw JSONL
- 95% CI of the mean uses Student's t (df = N-1)
- series with CV > 10% are flagged, never silently dropped
"""
import math


def mean(xs):
    return sum(xs) / len(xs)


def sigma(xs):
    if len(xs) < 2:
        return 0.0
    m = mean(xs)
    return math.sqrt(sum((x - m) ** 2 for x in xs) / (len(xs) - 1))


def percentile(xs, p):
    """Linear-interpolation percentile on a sorted copy (same as numpy default)."""
    if not xs:
        return 0.0
    s = sorted(xs)
    if len(s) == 1:
        return s[0]
    k = (len(s) - 1) * (p / 100.0)
    f = math.floor(k)
    c = min(f + 1, len(s) - 1)
    return s[f] + (s[c] - s[f]) * (k - f)


# Student's t for 95% two-sided, common N values; falls back to normal approx.
_T95 = {5: 2.776, 10: 2.262, 15: 2.145, 20: 2.093, 24: 2.069, 25: 2.064,
        30: 2.045, 40: 2.023, 50: 2.010, 60: 2.000, 100: 1.984, 200: 1.972}


def t95(n):
    if n in _T95:
        return _T95[n]
    if n < 5:
        return 3.182  # df=3, conservative for tiny samples
    return 1.96 + 2.0 / max(n - 1, 1) ** 0.6  # smooth decay toward normal


def summarize_samples(xs, unit="ms"):
    """Point-metric summary: mean, sigma, min, max, median, p90, p95, p99, CV, 95% CI."""
    if not xs:
        return {"n": 0, "unit": unit}
    m = mean(xs)
    s = sigma(xs)
    return {
        "n": len(xs),
        "unit": unit,
        "mean": round(m, 3),
        "sigma": round(s, 3),
        "min": round(min(xs), 3),
        "max": round(max(xs), 3),
        "median": round(percentile(xs, 50), 3),
        "p90": round(percentile(xs, 90), 3),
        "p95": round(percentile(xs, 95), 3),
        "p99": round(percentile(xs, 99), 3),
        "cv_pct": round(100.0 * s / m, 2) if m else None,
        "ci95_half": round(t95(len(xs)) * s / math.sqrt(len(xs)), 3) if len(xs) > 1 else 0.0,
    }


def histogram_log2(xs, unit="ms"):
    """Fixed log2-bucket histogram of a latency sample set.

    Bucket 0 covers [0, 2^0) in the given unit; bucket k (k >= 1) covers
    [2^(k-1), 2^k). Bounds are exact powers of two, deterministic given the
    data, so the shape of the distribution is inspectable from the aggregate
    without re-reading the raw JSONL.
    """
    if not xs:
        return {"unit": unit, "n": 0, "buckets": []}
    kmax = 0
    for x in xs:
        if x >= 1:
            kmax = max(kmax, int(math.floor(math.log2(x))) + 1)
    counts = [0] * (kmax + 1)
    for x in xs:
        if x < 1:
            k = 0
        else:
            k = min(int(math.floor(math.log2(x))) + 1, kmax)
        counts[k] += 1
    n = len(xs)
    buckets = []
    for k, c in enumerate(counts):
        lo = 0.0 if k == 0 else float(2 ** (k - 1))
        hi = float(2 ** k)
        buckets.append({"floor": lo, "ceil": hi, "count": c,
                        "share_pct": round(100.0 * c / n, 2)})
    return {"unit": unit, "n": n, "buckets": buckets}


def latency_summary(xs, unit="ms"):
    """Distribution summary for round-trip latencies: percentiles + histogram."""
    if not xs:
        return {"n": 0, "unit": unit}
    base = summarize_samples(xs, unit)
    base["p50"] = base["median"]
    base["histogram"] = histogram_log2(xs, unit)
    return base


def relative(a, b):
    """Relative speedup a/b with propagated sigma (a, b are summarize dicts)."""
    if not a or not b or not b.get("mean") or not a.get("mean"):
        return None
    r = a["mean"] / b["mean"]
    # propagation: sigma_r/r = sqrt((sa/a)^2 + (sb/b)^2)
    sa = a.get("sigma", 0.0) / a["mean"]
    sb = b.get("sigma", 0.0) / b["mean"]
    sr = r * math.sqrt(sa * sa + sb * sb)
    return {"ratio": round(r, 2), "sigma": round(sr, 2),
            "ci_overlap": _ci_overlap(a, b)}


def _ci_overlap(a, b):
    alo, ahi = a["mean"] - a.get("ci95_half", 0), a["mean"] + a.get("ci95_half", 0)
    blo, bhi = b["mean"] - b.get("ci95_half", 0), b["mean"] + b.get("ci95_half", 0)
    return not (ahi < blo or bhi < alo)
