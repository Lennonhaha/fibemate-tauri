#!/usr/bin/env python3
"""P2 performance regression CI gate.

Reads criterion estimates from target/criterion/<group>/<bench>/new/estimates.json
(most recent `cargo bench` run) and compares the mean against thresholds in
perf_thresholds.json (microseconds). Exits 1 if any metric exceeds its threshold.

Percentiles (p50/p95/p99) are derived from criterion's raw per-iteration
samples in .../new/sample.json, because criterion's estimates.json only stores
mean/median/std_dev. Tail latency matters most for the concurrent benchmarks,
where a regression shows up in p95/p99 long before it moves the mean. A metric
is additionally gated on p95 when a "<metric>:p95" key exists in the
thresholds file (the mean gate always applies).

Memory footprint is gated separately: benches/memory.rs writes live-heap
bytes to target/criterion/memory.json, checked against
memory_thresholds.json (KB).

Usage:
    cargo bench                      # produce fresh estimates
    python scripts/perf_check.py     # enforce thresholds

    python scripts/perf_check.py --update   # rewrite thresholds from current run
                                           # (x safety factor) — use on hardware
                                           # baseline changes only
    python scripts/perf_check.py --criterion-dir PATH   # override criterion output
                                                        # dir (e.g. custom
                                                        # CARGO_TARGET_DIR builds)
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # src-tauri/
THRESHOLDS = Path(__file__).resolve().parent / "perf_thresholds.json"
MEMORY_THRESHOLDS = Path(__file__).resolve().parent / "memory_thresholds.json"
SAFETY_FACTOR = 3.0  # thresholds = baseline mean x 3 (CI machines are noisy)
P95_SUFFIX = ":p95"


def percentile(sorted_values: list, q: float) -> float:
    """Linear-interpolated percentile on an already-sorted list."""
    if not sorted_values:
        return float("nan")
    if len(sorted_values) == 1:
        return sorted_values[0]
    pos = (len(sorted_values) - 1) * q
    lo, hi = int(pos), min(int(pos) + 1, len(sorted_values) - 1)
    if lo == hi:
        return sorted_values[lo]
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (pos - lo)


def load_sample_percentiles(sample_path: Path) -> dict:
    """p50/p95/p99 in microseconds from criterion's raw per-iteration samples.

    sample.json stores, per sample, the iteration count and the TOTAL duration
    for that many iterations, so the per-iteration time is total / iters.
    """
    with sample_path.open() as f:
        data = json.load(f)
    iters = data.get("iters") or []
    times = data.get("times") or []
    per_iter = sorted(t / i for t, i in zip(times, iters) if i)
    if not per_iter:
        return {}
    return {
        "p50": percentile(per_iter, 0.50) / 1000.0,
        "p95": percentile(per_iter, 0.95) / 1000.0,
        "p99": percentile(per_iter, 0.99) / 1000.0,
    }


def resolve_criterion_dir(argv: list) -> Path:
    """Return the criterion output dir (default target/criterion, overridable)."""
    for i, arg in enumerate(argv):
        if arg == "--criterion-dir" and i + 1 < len(argv):
            return Path(argv[i + 1])
    return ROOT / "target" / "criterion"


def load_estimates(criterion_dir: Path) -> dict:
    """Collect {group/bench: mean_ns} from the newest criterion run."""
    if not criterion_dir.is_dir():
        sys.exit(f"ERROR: {criterion_dir} not found — run `cargo bench` first")
    out = {}
    for est in criterion_dir.glob("*/*/new/estimates.json"):
        group = est.parent.parent.parent.name
        bench = est.parent.parent.name
        with est.open() as f:
            data = json.load(f)
        mean_ns = data["mean"]["point_estimate"]
        out[f"{group}/{bench}"] = mean_ns
    return out


def load_percentiles(criterion_dir: Path) -> dict:
    """Collect {group/bench: {p50,p95,p99}} in microseconds from raw samples."""
    out = {}
    for sample in criterion_dir.glob("*/*/new/sample.json"):
        group = sample.parent.parent.parent.name
        bench = sample.parent.parent.name
        pcts = load_sample_percentiles(sample)
        if pcts:
            out[f"{group}/{bench}"] = pcts
    return out


def load_memory(criterion_dir: Path) -> dict:
    """{metric: live_bytes} written by benches/memory.rs."""
    path = criterion_dir / "memory.json"
    if not path.is_file():
        return {}
    with path.open() as f:
        return json.load(f)


def main() -> int:
    argv = sys.argv
    criterion_dir = resolve_criterion_dir(argv)
    estimates = load_estimates(criterion_dir)
    if not estimates:
        sys.exit("ERROR: no estimates found — run `cargo bench` first")
    percentiles = load_percentiles(criterion_dir)

    if "--update" in argv:
        thresholds = {k: round(v / 1000 * SAFETY_FACTOR, 1) for k, v in estimates.items()}
        if "--with-p95" in argv:
            for key, pcts in percentiles.items():
                if key in thresholds:
                    thresholds[key + P95_SUFFIX] = round(
                        pcts["p95"] * SAFETY_FACTOR, 1
                    )
        with THRESHOLDS.open("w") as f:
            json.dump(thresholds, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"Wrote {len(thresholds)} thresholds (baseline x {SAFETY_FACTOR}) to {THRESHOLDS.name}")
        return 0

    if not THRESHOLDS.is_file():
        sys.exit(f"ERROR: {THRESHOLDS} not found — run with --update once on the baseline machine")

    with THRESHOLDS.open() as f:
        thresholds = json.load(f)

    failures = []
    print(f"{'metric':<38} {'mean':>10} {'p50':>9} {'p95':>9} {'p99':>9} {'threshold':>11}  status")
    print("-" * 94)
    for key, mean_ns in sorted(estimates.items()):
        mean_us = mean_ns / 1000
        pcts = percentiles.get(key, {})
        cells = "".join(f"{pcts.get(p, float('nan')):>8.1f} " for p in ("p50", "p95", "p99"))
        limit = thresholds.get(key)
        if limit is None:
            print(f"{key:<38} {mean_us:>9.1f}us {cells} {'(no threshold)':>11}  SKIP")
            continue
        status = "OK" if mean_us <= limit else "FAIL"
        if mean_us > limit:
            failures.append(key)
        # Optional tail gate: only applies when a "<metric>:p95" threshold exists.
        p95_limit = thresholds.get(key + P95_SUFFIX)
        if p95_limit is not None and pcts:
            if pcts["p95"] > p95_limit:
                status = "FAIL"
                failures.append(key + P95_SUFFIX)
        limit_cell = f"{limit:.1f}us"
        if p95_limit is not None:
            limit_cell = f"{limit:.1f}/p95 {p95_limit:.0f}"
        print(f"{key:<38} {mean_us:>9.1f}us {cells} {limit_cell:>11}  {status}")

    gated = set(estimates) & set(thresholds)
    missing = set(thresholds) - set(estimates) - {k + P95_SUFFIX for k in estimates}
    for key in sorted(missing):
        print(f"{key:<38} {'—':>10} {'—':>9} {'—':>9} {'—':>9} {'—':>11}  MISSING (no measurement)")

    # ── Memory footprint (benches/memory.rs) ────────────────────
    mem = load_memory(criterion_dir)
    if mem:
        mem_limits = {}
        if MEMORY_THRESHOLDS.is_file():
            with MEMORY_THRESHOLDS.open() as f:
                mem_limits = json.load(f)
        print(f"\n{'metric':<38} {'live':>12} {'threshold':>12}  status")
        print("-" * 68)
        for key, raw_bytes in sorted(mem.items()):
            live_kb = raw_bytes / 1024
            limit = mem_limits.get(key)
            if limit is None:
                print(f"{key:<38} {live_kb:>10.1f}KB {'(no threshold)':>12}  SKIP")
                continue
            status = "OK" if live_kb <= limit else "FAIL"
            if live_kb > limit:
                failures.append(key)
            print(f"{key:<38} {live_kb:>10.1f}KB {limit:>10.1f}KB  {status}")
            gated.add(key)

    if failures:
        print(f"\nPERF REGRESSION: {len(failures)} metric(s) exceeded threshold(s)")
        return 1
    print(f"\nAll {len(gated)} gated metrics within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
