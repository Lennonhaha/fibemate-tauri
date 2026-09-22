/**
 * load-zk-if-enabled.js — Runtime gate for the experimental ZK module.
 *
 * The `src/zk/*` modules (PBKDF2 key derivation + P-256 Schnorr/Bulletproofs
 * proofs) run in the JS/WebView layer and are NOT wired to the Rust backend.
 * They are experimental and DEFAULT-OFF. This bootstrap consults the single
 * Rust source of truth (`get_experiments()`) and only injects the ZK scripts
 * when `FIBEMATE_EXPERIMENT_ZK` is set (process-start env, on the Rust side).
 *
 * Design: fail-closed. If we are not inside Tauri, or the invoke fails, or the
 * flag is off, NO `src/zk/*` code is loaded or executed, and the ZK UI toggle
 * (`[data-setting="zkMode"]`) is hidden. The standard login polyfill
 * (`fibemate-zk-polyfill.js`) is intentionally OUTSIDE this gate — it provides
 * the production baseline login and is not an experiment.
 */

(function () {
  'use strict';

  // ZK modules to load only when the experiment flag is on.
  // Order matters: browser compat layer first, then prover/bulletproofs,
  // then auth/integration, then UI integration last.
  var ZK_SCRIPTS = [
    'zk/zk-browser.js',
    'zk/schnorr-prover-v2.js',
    'zk/bulletproofs.js',
    'zk/zk-auth.js',
    'zk/zk-integration.js',
    'zk-ui-integration.js'
  ];

  function getInvoke() {
    if (typeof window !== 'undefined' && window.__TAURI__ && window.__TAURI__.core && window.__TAURI__.core.invoke) {
      return window.__TAURI__.core.invoke;
    }
    return null;
  }

  async function zkEnabled() {
    var invoke = getInvoke();
    if (!invoke) return false; // not in Tauri → fail closed
    try {
      var ex = await invoke('get_experiments');
      return !!(ex && ex.zk);
    } catch (e) {
      console.warn('[load-zk] get_experiments failed, defaulting off:', e && e.message);
      return false; // fail closed
    }
  }

  function hideZkToggle() {
    var toggle = document.querySelector('[data-setting="zkMode"]');
    if (toggle) {
      toggle.disabled = true;
      toggle.style.display = 'none';
      var row = toggle.closest('.setting-row') || toggle.closest('[data-setting-row]');
      if (row) row.style.display = 'none';
    }
  }

  function injectScript(src) {
    return new Promise(function (resolve) {
      var el = document.createElement('script');
      el.src = src;
      el.onload = resolve;
      el.onerror = function () { console.warn('[load-zk] failed to load', src); resolve(); };
      document.head.appendChild(el);
    });
  }

  async function loadZk() {
    var enabled = await zkEnabled();
    if (!enabled) {
      hideZkToggle();
      console.log('[load-zk] ZK experiment disabled (default) — no src/zk/* loaded.');
      return;
    }
    for (var i = 0; i < ZK_SCRIPTS.length; i++) {
      await injectScript(ZK_SCRIPTS[i]);
    }
    console.log('[load-zk] ZK experiment enabled — src/zk/* loaded.');
  }

  if (typeof document !== 'undefined') {
    if (document.readyState === 'loading') {
      document.addEventListener('DOMContentLoaded', loadZk);
    } else {
      loadZk();
    }
  }
})();
