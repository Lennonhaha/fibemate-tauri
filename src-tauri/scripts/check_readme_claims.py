#!/usr/bin/env python3
"""Verify the counts documented in README match the code.

The README states the number of passing tests (once, in the "Run Tests"
snippet) and the number of registered Tauri commands (in an architecture
diagram and a command table). Every one is hand-typed, so they drift the
moment anyone adds a test or a command - and nothing fails when they do, so
the docs quietly start lying.

(The test badge is a live CI-status badge, so it no longer carries a number;
its workflow URL is asserted separately by FORMAT_CLAIMS.)

This turns those numbers into checked assertions. It exits non-zero on any
mismatch, and `--update` rewrites them all in place.

Usage:
    cargo test --all-features -- --list > test_list.txt
    python scripts/check_readme_claims.py --list test_list.txt

    python scripts/check_readme_claims.py --update    # rewrite documented counts
"""

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent  # repo root
README = ROOT / "README.md"
LIB = ROOT / "src-tauri" / "src" / "lib.rs"


def read_text(path: Path) -> str:
    """Read without newline translation, so rewriting cannot flip CRLF <-> LF."""
    with path.open(encoding="utf-8", newline="") as f:
        return f.read()


def write_text(path: Path, text: str) -> None:
    with path.open("w", encoding="utf-8", newline="") as f:
        f.write(text)


def count_tests(list_path: Path) -> int:
    """Count 'name: test' lines from `cargo test -- --list`."""
    return sum(
        1
        for line in list_path.read_text(encoding="utf-8", errors="replace").splitlines()
        if line.rstrip().endswith(": test")
    )


def count_commands() -> int:
    """Count entries in `tauri::generate_handler![...]`.

    Entries mix bare names with paths (`commands::kem::kem_keygen`) and the
    list carries `// group` comments, so strip comments and take the last `::`
    segment - matching the module prefix would nearly triple the count.
    """
    src = read_text(LIB)
    m = re.search(r"generate_handler!\s*\[(.*?)\n\s*\]", src, re.S) or re.search(
        r"generate_handler!\s*\[(.*?)\]", src, re.S
    )
    if not m:
        sys.exit(f"ERROR: no generate_handler! block found in {LIB}")
    body = re.sub(r"//[^\n]*", "", m.group(1))
    return len([t for t in (x.strip() for x in body.split(",")) if t])


# (label, regex, replacement) - every capture group must equal the real value.
TEST_CLAIMS = [
    ("expected tests comment", re.compile(r"Expected:\s*(\d+)\s+tests"), r"Expected: {n} tests"),
]

COMMAND_CLAIMS = [
    ("architecture diagram", re.compile(r"│ (\d+) Tauri commands"), r"│ {n} Tauri commands"),
    (
        "lib.rs annotation",
        re.compile(r"App entry \+ (\d+) command registrations"),
        r"App entry + {n} command registrations",
    ),
    (
        "command table header",
        re.compile(r"### Tauri Commands \((\d+) registered"),
        r"### Tauri Commands ({n} registered",
    ),
]

# Non-numeric claims: README must keep matching these (format / URL guards).
# The test badge is now a live CI-status badge, so it no longer carries a
# number; we still assert its workflow URL so nobody silently reverts it to a
# stale hand-typed count.
FORMAT_CLAIMS = [
    (
        "badge",
        re.compile(
            r"shields\.io/github/actions/workflow/status/Lennonhaha/fibemate-tauri/ci\.yml"
        ),
    ),
]

ALL_CLAIMS = TEST_CLAIMS + COMMAND_CLAIMS


def first_group(pattern: re.Pattern, text: str) -> str:
    m = pattern.search(text)
    return next(g for g in m.groups() if g is not None) if m else ""


def run_checks(text: str, counts: dict) -> list:
    """Print one table per claim group; return a list of failures."""
    failures = []
    for group, (claims, actual, unit) in counts.items():
        print(f"{'claim':<26} {'documented':>12}  status   [{group}, actual {actual}]")
        print("-" * 62)
        for label, pattern, _ in claims:
            found = pattern.findall(text)
            if not found:
                print(f"{label:<26} {'—':>12}  NOT FOUND (regex no longer matches)")
                failures.append(f"{group}/{label} (regex stale)")
                continue
            value = first_group(pattern, text)
            ok = value and int(value) == actual
            for groups in found:
                vals = groups if isinstance(groups, tuple) else (groups,)
                if any(int(v) != actual for v in vals):
                    ok = False
            print(f"{label:<26} {value or '?':>12}  {'OK' if ok else 'FAIL'}")
            if not ok:
                failures.append(f"{group}/{label} (says {value})")
        print()
    if FORMAT_CLAIMS:
        print(f"{'claim':<26} {'documented':>12}  status   [format, must be present]")
        print("-" * 62)
        for label, pattern in FORMAT_CLAIMS:
            if pattern.search(text):
                print(f"{label:<26} {'ok':>12}  OK")
            else:
                print(f"{label:<26} {'—':>12}  NOT FOUND (expected format)")
                failures.append(f"format/{label}")
        print()
    return failures


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--list",
        type=Path,
        help="output of `cargo test -- --list` (omit to check command count only)",
    )
    ap.add_argument("--update", action="store_true", help="rewrite README with the real counts")
    args = ap.parse_args()

    if not README.is_file():
        sys.exit(f"ERROR: {README} not found")
    text = read_text(README)

    actual_commands = count_commands()
    actual_tests = None
    if args.list:
        if not args.list.is_file():
            sys.exit(f"ERROR: {args.list} not found — run `cargo test --all-features -- --list` first")
        actual_tests = count_tests(args.list)
        if actual_tests == 0:
            sys.exit(f"ERROR: no tests listed in {args.list} — is it really `--list` output?")

    if args.update:
        for _, pattern, tmpl in TEST_CLAIMS:
            if actual_tests is not None:
                text = pattern.sub(tmpl.format(n=actual_tests), text)
        for _, pattern, tmpl in COMMAND_CLAIMS:
            text = pattern.sub(tmpl.format(n=actual_commands), text)
        write_text(README, text)
        print(f"README updated: {actual_tests} tests, {actual_commands} commands")
        return 0

    counts = {"commands": (COMMAND_CLAIMS, actual_commands, "commands")}
    if actual_tests is not None:
        counts = {"tests": (TEST_CLAIMS, actual_tests, "tests"), **counts}

    failures = run_checks(text, counts)
    if failures:
        print(f"DOC DRIFT: {len(failures)} claim(s) disagree with the code — first: {failures[0]}")
        print("           fix with: python scripts/check_readme_claims.py --update")
        return 1
    print(f"README claims match the code ({actual_tests} tests, {actual_commands} commands)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
