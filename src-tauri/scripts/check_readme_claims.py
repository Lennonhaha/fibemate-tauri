#!/usr/bin/env python3
"""Verify the test count documented in README matches reality.

The README states the passing test count in several places: a shields.io badge,
an "expected output" snippet, and a release checklist item. Every one of them
is a hand-typed number, so they drift the moment anyone adds or removes a test
- and nothing fails when they do, so the badge quietly starts lying.

This turns those numbers into a checked assertion. It reads the list produced
by `cargo test -- --list` and compares it against every count the README
claims, failing on any mismatch.

Usage:
    cargo test --all-features -- --list > test_list.txt
    python scripts/check_readme_tests.py --list test_list.txt

    python scripts/check_readme_tests.py --list test_list.txt --update
        # rewrite the documented counts in place
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent  # repo root
README = ROOT / "README.md"

# (label, regex) — every capture group must equal the real test count.
# The badge URL-encodes its slash, which is why it needs its own pattern.
CLAIMS = [
    ("badge", re.compile(r"tests-(\d+)%2F(\d+)%20passed")),
    ("expected-output comment", re.compile(r"Expected:\s*(\d+)\s+tests")),
    ("sample test result", re.compile(r"^test result: ok\. (\d+) passed", re.M)),
    ("checklist", re.compile(r"(\d+)/(\d+) lib tests passing")),
]


def read_text(path: Path) -> str:
    """Read without newline translation, so rewriting cannot flip CRLF <-> LF."""
    with path.open(encoding="utf-8", newline="") as f:
        return f.read()


def write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write(text)


def count_tests(list_path: Path) -> int:
    """Count 'name: test' lines from `cargo test -- --list`."""
    n = 0
    for line in list_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.rstrip().endswith(": test"):
            n += 1
    return n


def update_readme(text: str, actual: int) -> str:
    text = re.sub(r"tests-\d+%2F\d+%20passed", f"tests-{actual}%2F{actual}%20passed", text)
    text = re.sub(r"Expected:\s*\d+\s+tests", f"Expected: {actual} tests", text)
    text = re.sub(
        r"^test result: ok\. \d+ passed",
        f"test result: ok. {actual} passed",
        text,
        flags=re.M,
    )
    text = re.sub(r"\d+/\d+ lib tests passing", f"{actual}/{actual} lib tests passing", text)
    return text


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", required=True, type=Path, help="output of `cargo test -- --list`")
    ap.add_argument("--update", action="store_true", help="rewrite README with the real count")
    args = ap.parse_args()

    if not args.list.is_file():
        sys.exit(f"ERROR: {args.list} not found — run `cargo test --all-features -- --list` first")
    actual = count_tests(args.list)
    if actual == 0:
        sys.exit(f"ERROR: no tests listed in {args.list} — is it really `--list` output?")

    if not README.is_file():
        sys.exit(f"ERROR: {README} not found")

    text = read_text(README)
    if args.update:
        write_text(README, update_readme(text, actual))
        print(f"README: documented test count updated to {actual}")
        return 0

    failures = []
    missing = []
    for label, pattern in CLAIMS:
        found = pattern.findall(text)
        if not found:
            missing.append(label)
            continue
        for groups in found:
            for value in (groups if isinstance(groups, tuple) else (groups,)):
                if int(value) != actual:
                    failures.append((label, value, actual))

    print(f"actual test count: {actual}")
    print(f"{'claim':<26} {'documented':>12}  status")
    print("-" * 48)
    for label, _ in CLAIMS:
        if label in missing:
            print(f"{label:<26} {'—':>12}  NOT FOUND (regex no longer matches README)")
            continue
        documented = CLAIMS[[c[0] for c in CLAIMS].index(label)][1].search(text)
        value = next(
            g for g in (documented.groups() if documented else ()) if g is not None
        )
        status = "OK" if int(value) == actual else "FAIL"
        print(f"{label:<26} {value:>12}  {status}")

    if missing:
        print(f"\nERROR: {len(missing)} claim pattern(s) matched nothing — the check itself is stale")
        return 1
    if failures:
        print(f"\nDOC DRIFT: README says {failures[0][1]} but {failures[0][2]} tests exist")
        print("           fix with: python scripts/check_readme_tests.py --list <list> --update")
        return 1
    print(f"\nREADME test count matches: all {len(CLAIMS)} claims say {actual}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
