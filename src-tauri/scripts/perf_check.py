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
bytes to target/criterion/memory.json, checked against memory_thresholds.json
(bytes). Unlike the timing metrics, these reproduce byte-for-byte across
platforms and runs, so MEMORY_SAFETY_FACTOR is 1.5 rather than 3.

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
import platform
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent  # src-tauri/
THRESHOLDS = Path(__file__).resolve().parent / "perf_thresholds.json"
MEMORY_THRESHOLDS = Path(__file__).resolve().parent / "memory_thresholds.json"
SAFETY_FACTOR = 3.0  # thresholds = baseline mean x 3 (CI machines are noisy)
# Memory is measured with a counting allocator, not a clock: it reproduces
# byte-identically across platforms and runs, so it needs no noise margin.
# The margin below only absorbs benign layout drift (String capacities, an
# extra Option field) and the toolchain is on unpinned `stable`, whose
# hashbrown bucket policy is free to change.
MEMORY_SAFETY_FACTOR = 1.5
# `ratchet_state_size_bytes` is a compile-time constant: zero noise and no hash
# table slack, so a multiplicative margin is the wrong shape. It gets a flat
# allowance for one or two small fields; anything larger should be a reviewed
# baseline update rather than something CI waves through.
MEMORY_SLACK_BYTES = {"ratchet_state_size_bytes": 64}
P95_SUFFIX = ":p95"
# Keys starting with this are metadata, not gated metrics.
META_PREFIX = "_"
SOURCE_PLATFORM_KEY = "_source_platform"


def human_bytes(n: float) -> str:
    """Format a byte count, keeping resolution for small values.

    A bare KB rendering turns the 384-byte `ratchet_state_size_bytes` into
    "0.4KB", which hides the very single-field changes it exists to catch.
    """
    if n < 1024:
        return f"{n:.0f} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / 1024 / 1024:.1f} MB"


def strip_meta(name: str, thresholds: dict, *, platform_sensitive: bool = True) -> None:
    """Drop metadata keys; shout if timing baselines came from another OS.

    keystore/load_32b_secret and persistence/save_50_sessions_encrypted sat at
    40-100x their real CI values because they were recorded on Windows - DPAPI
    and NTFS - and then enforced on Linux. A cross-platform baseline makes the
    gate either dead or flapping, and neither failure mode is visible from the
    gate output alone, so it has to be said out loud.

    Memory thresholds opt out via `platform_sensitive=False`: a counting
    allocator reproduces byte-identically, so their baselines really are
    portable and warning about them would be noise.
    """
    source = thresholds.pop(SOURCE_PLATFORM_KEY, None)
    for key in [k for k in thresholds if k.startswith(META_PREFIX)]:
        thresholds.pop(key)
    if platform_sensitive and source and source != platform.system():
        print(
            f"WARNING: {name} was recorded on {source}, but this gate runs on "
            f"{platform.system()}. Absolute timings are not comparable across "
            f"platforms — re-derive with --update here."
        )


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
    mem = load_memory(criterion_dir)

    if "--update" in argv:
        thresholds = {k: round(v / 1000 * SAFETY_FACTOR, 1) for k, v in estimates.items()}
        if "--with-p95" in argv:
            for key, pcts in percentiles.items():
                if key in thresholds:
                    thresholds[key + P95_SUFFIX] = round(
                        pcts["p95"] * SAFETY_FACTOR, 1
                    )
        thresholds[SOURCE_PLATFORM_KEY] = platform.system()
        with THRESHOLDS.open("w") as f:
            json.dump(thresholds, f, indent=2, sort_keys=True)
            f.write("\n")
        print(f"Wrote {len(thresholds)} thresholds (baseline x {SAFETY_FACTOR}) to {THRESHOLDS.name}")
        if mem:
            mem_limits = {
                k: v + MEMORY_SLACK_BYTES[k]
                if k in MEMORY_SLACK_BYTES
                else int(round(v * MEMORY_SAFETY_FACTOR))
                for k, v in mem.items()
            }
            mem_limits[SOURCE_PLATFORM_KEY] = platform.system()
            with MEMORY_THRESHOLDS.open("w") as f:
                json.dump(mem_limits, f, indent=2, sort_keys=True)
                f.write("\n")
            print(
                f"Wrote {len(mem_limits)} memory thresholds "
                f"(baseline x {MEMORY_SAFETY_FACTOR}) to {MEMORY_THRESHOLDS.name}"
            )
        return 0

    if not THRESHOLDS.is_file():
        sys.exit(f"ERROR: {THRESHOLDS} not found — run with --update once on the baseline machine")

    with THRESHOLDS.open() as f:
        thresholds = json.load(f)
    strip_meta(THRESHOLDS.name, thresholds)

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
    if mem:
        mem_limits = {}
        if MEMORY_THRESHOLDS.is_file():
            with MEMORY_THRESHOLDS.open() as f:
                mem_limits = json.load(f)
            strip_meta(
                MEMORY_THRESHOLDS.name, mem_limits, platform_sensitive=False
            )
        print(f"\n{'metric':<38} {'live':>12} {'threshold':>12}  status")
        print("-" * 68)
        for key, raw_bytes in sorted(mem.items()):
            limit = mem_limits.get(key)
            if limit is None:
                print(f"{key:<38} {human_bytes(raw_bytes):>12} {'(no threshold)':>12}  SKIP")
                continue
            status = "OK" if raw_bytes <= limit else "FAIL"
            if raw_bytes > limit:
                failures.append(key)
            print(f"{key:<38} {human_bytes(raw_bytes):>12} {human_bytes(limit):>12}  {status}")
            gated.add(key)

    if failures:
        print(f"\nPERF REGRESSION: {len(failures)} metric(s) exceeded threshold(s)")
        return 1
    print(f"\nAll {len(gated)} gated metrics within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
