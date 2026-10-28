#!/usr/bin/env node
// SPDX-License-Identifier: GPL-3.0-only
/**
 * scripts/test-pq-availability.cjs — the PQ availability flag must describe the
 * engine that will actually do the work, and the retired pure-JS KEM must be gone.
 *
 * Background (issue #77): a pure-JS ML-KEM wrapper used to be loaded before
 * tauri-crypto-bridge.js. It set `initialized = true` immediately, pq-integration
 * cached it during a 5 s poll, and the bridge replaced window.MLKEM768 too late.
 * Result: PQIntegration.isAvailable() returned true while the JS module never
 * performed keygen/encaps/decaps — the UI showed a post-quantum badge backed by
 * nothing. This test fails if that shape comes back:
 *
 *   1. no tracked source references the retired files,
 *   2. the retired files do not exist,
 *   3. inside Tauri, isAvailable() is true AND encapsulation reaches the
 *      Rust command (kem_encapsulate),
 *   4. outside Tauri, isAvailable() is false,
 *   5. an uninitialized / non-functional engine is not reported as available.
 */

'use strict';

const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { execFileSync } = require('node:child_process');

const ROOT = path.resolve(__dirname, '..');
let failed = 0;
const check = (name, ok, detail) => {
  if (ok) {
    console.log(`PASS  ${name}`);
  } else {
    failed += 1;
    console.log(`FAIL  ${name}${detail ? ' — ' + detail : ''}`);
  }
};

// ── 1/2. static: retired files and their references are gone ────────────────
const retired = [
  'src/crypto/crypto/ml-kem-768.js',
  'src/crypto/crypto/ml-kem-768-wrapper.js',
];
for (const rel of retired) {
  check(`${rel} is absent`, !fs.existsSync(path.join(ROOT, rel)));
}

const tracked = execFileSync('git', ['ls-files', 'src'], { cwd: ROOT, encoding: 'utf8' })
  .split('\n')
  .filter((f) => /\.(html|js|mjs|cjs)$/.test(f));
const offenders = [];
// A mention in prose is fine; a load is not. Match only the ways a page or a
// script can actually pull the module in.
const LOAD = /(?:<script[^>]*src=["'][^"']*ml-kem-768[^"']*["'])|(?:require\(\s*['"][^'"]*ml-kem-768[^'"]*['"]\s*\))|(?:from\s+['"][^'"]*ml-kem-768[^'"]*['"])|(?:readFileSync\([^)]*ml-kem-768)/;
for (const rel of tracked) {
  const text = fs.readFileSync(path.join(ROOT, rel), 'utf8');
  if (LOAD.test(text)) offenders.push(rel);
}
check('no source file references the retired KEM', offenders.length === 0, offenders.join(', '));

// ── harness: load the two browser scripts in a sandbox ──────────────────────
function makeSandbox({ tauri }) {
  const calls = [];
  const sandbox = {
    console: { log() {}, warn() {}, error() {} },
    setTimeout,
    clearTimeout,
    Uint8Array,
    Promise,
    crypto: {},
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  if (tauri) {
    sandbox.__TAURI__ = {
      core: {
        invoke: async (cmd, args) => {
          calls.push({ cmd, args });
          if (cmd === 'kem_keygen') return { key_id: 'kid-1', public_key: '00' };
          if (cmd === 'kem_encapsulate') return { ciphertext: '00', ss_id: 'ss-1' };
          if (cmd === 'kem_decapsulate') return { ss_id: 'ss-2' };
          throw new Error('unexpected command ' + cmd);
        },
      },
    };
  }
  const ctx = vm.createContext(sandbox);
  const load = (rel) => vm.runInContext(fs.readFileSync(path.join(ROOT, rel), 'utf8'), ctx, { filename: rel });
  for (const rel of ['src/tauri-crypto-bridge.js', 'src/crypto/crypto/pq-integration.js']) load(rel);
  return { sandbox, calls, ctx, load };
}

(async () => {
  // ── 3. inside Tauri: available, and encapsulation really goes to Rust ─────
  {
    const { sandbox, calls } = makeSandbox({ tauri: true });
    await new Promise((r) => setTimeout(r, 30));
    const PQ = sandbox.PQIntegration;
    check('Tauri: PQIntegration exists', !!PQ);
    check('Tauri: isAvailable() is true', PQ.isAvailable() === true);
    const status = PQ.getStatus();
    check('Tauri: engine reported as tauri', status.engine === 'tauri', JSON.stringify(status));

    const out = await PQ.encapsulate(new Uint8Array(1184));
    const encapsCall = calls.find((c) => c.cmd === 'kem_encapsulate');
    check('Tauri: encapsulate invokes kem_encapsulate', !!encapsCall);
    check('Tauri: encapsulate returns a ciphertext', out && out.ciphertext instanceof Uint8Array);
    check('Tauri: shared secret stays opaque (ssId, no raw secret)',
      out && typeof out.ssId === 'string' && !('sharedSecret' in out) && !('shared_secret' in out));
  }

  // ── 3b. real load order: pq-integration runs before tauri-crypto-bridge ───
  // This is how index.html and main.html order their script tags. The probe must
  // wait for the bridge instead of latching "unavailable" on first look.
  {
    const { sandbox, load } = makeSandbox({ tauri: false });
    delete sandbox.__TAURI__;
    await new Promise((r) => setTimeout(r, 150));
    check('load order: not available before the bridge script runs',
      sandbox.PQIntegration.isAvailable() === false);
    sandbox.__TAURI__ = { core: { invoke: async (cmd) => {
      if (cmd === 'kem_encapsulate') return { ciphertext: '00', ss_id: 'ss-1' };
      throw new Error('unexpected ' + cmd);
    } } };
    load('src/tauri-crypto-bridge.js');
    await new Promise((r) => setTimeout(r, 400));
    check('load order: becomes available once the bridge loads',
      sandbox.PQIntegration.isAvailable() === true);
    check('load order: engine reported as tauri',
      sandbox.PQIntegration.getStatus().engine === 'tauri');
  }

  // ── 4. outside Tauri: not available (classical fallback must say so) ──────
  {
    const { sandbox } = makeSandbox({ tauri: false });
    await new Promise((r) => setTimeout(r, 30));
    check('non-Tauri: isAvailable() is false', sandbox.PQIntegration.isAvailable() === false);
    check('non-Tauri: engine reported as none', sandbox.PQIntegration.getStatus().engine === 'none');
  }

  // ── 5. a loaded-but-non-functional engine must not count as available ─────
  {
    const { sandbox } = makeSandbox({ tauri: false });
    sandbox.MLKEM768 = { initialized: true }; // what the deleted wrapper looked like
    await new Promise((r) => setTimeout(r, 30));
    check('sham engine (initialized, no encaps) is not available',
      sandbox.PQIntegration.isAvailable() === false);
  }

  console.log(`\n${failed === 0 ? 'OK' : 'FAILED'}: ${failed} failure(s)`);
  process.exit(failed === 0 ? 0 : 1);
})();
