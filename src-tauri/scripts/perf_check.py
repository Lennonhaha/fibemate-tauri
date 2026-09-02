#!/usr/bin/env python3
"""P2 performance regression CI gate.

Reads criterion estimates from target/criterion/<group>/<bench>/new/estimates.json
(most recent `cargo bench` run) and compares the mean against thresholds in
perf_thresholds.json (microseconds). Exits 1 if any metric exceeds its threshold.

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
SAFETY_FACTOR = 3.0  # thresholds = baseline mean x 3 (CI machines are noisy)


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


def main() -> int:
    argv = sys.argv
    criterion_dir = resolve_criterion_dir(argv)
    estimates = load_estimates(criterion_dir)
    if not estimates:
        sys.exit("ERROR: no estimates found — run `cargo bench` first")

    if "--update" in argv:
        thresholds = {k: round(v / 1000 * SAFETY_FACTOR, 1) for k, v in estimates.items()}
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
    print(f"{'metric':<40} {'mean':>12} {'threshold':>12}  status")
    print("-" * 74)
    for key, mean_ns in sorted(estimates.items()):
        mean_us = mean_ns / 1000
        limit = thresholds.get(key)
        if limit is None:
            print(f"{key:<40} {mean_us:>10.1f}us {'(no threshold)':>12}  SKIP")
            continue
        status = "OK" if mean_us <= limit else "FAIL"
        print(f"{key:<40} {mean_us:>10.1f}us {limit:>10.1f}us  {status}")
        if mean_us > limit:
            failures.append(key)

    missing = set(thresholds) - set(estimates)
    for key in sorted(missing):
        print(f"{key:<40} {'—':>12} {'—':>12}  MISSING (no measurement)")

    if failures:
        print(f"\nPERF REGRESSION: {len(failures)} metric(s) exceeded threshold(s)")
        return 1
    print(f"\nAll {len([k for k in estimates if k in thresholds])} gated metrics within thresholds")
    return 0


if __name__ == "__main__":
    sys.exit(main())
