#!/usr/bin/env bash
# Assert that the ZK experimental module is NOT loaded unconditionally in the
# WebView entry points. The module is only allowed to load via the
# feature-flag gate (load-zk-if-enabled.js -> get_experiments() -> dynamic
# import). A regression that re-adds a plain <script src="zk/..."> would silently
# turn the default-off experiment back on, so fail the build if any are found.
#
# Allowed scripts (intentionally outside the gate):
#   - fibemate-zk-polyfill.js : auth bridge, NOT a zk feature
#   - load-zk-if-enabled.js    : the gate itself
set -euo pipefail

# Patterns that must NOT appear as an unconditional script tag.
ZK_SCRIPTS=(
  'zk/zk-browser.js'
  'zk/schnorr-prover-v2.js'
  'zk/bulletproofs.js'
  'zk/zk-auth.js'
  'zk/zk-integration.js'
  'zk-ui-integration.js'
)

ENTRIES=('src/index.html' 'src/main.html')

rc=0
for entry in "${ENTRIES[@]}"; do
  if [[ ! -f "$entry" ]]; then
    echo "[assert-no-unconditional-zk] SKIP: $entry not found"
    continue
  fi
  for s in "${ZK_SCRIPTS[@]}"; do
    # Match a <script ...> tag that directly references the zk module path.
    # Allow-list: must NOT match load-zk-if-enabled.js or fibemate-zk-polyfill.js.
    if grep -Eq "<script[^>]*src=\"[^\"]*${s}\"" "$entry"; then
      echo "[assert-no-unconditional-zk] FAIL: unconditional zk script found in $entry: $s"
      rc=1
    fi
  done
done

if [[ "$rc" -eq 0 ]]; then
  echo "[assert-no-unconditional-zk] PASS: no unconditional zk <script> in entry HTML"
fi
exit "$rc"